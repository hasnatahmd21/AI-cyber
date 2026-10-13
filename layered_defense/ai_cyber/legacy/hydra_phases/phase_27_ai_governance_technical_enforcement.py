"""
HYDRA POST-CORE — PHASE 27: AI GOVERNANCE + TECHNICAL ENFORCEMENT
====================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * AI inventory — models, agents, tools, datasets, providers,
    applications, prompts (asset kinds)
  * Lifecycle state — draft / staged / approved / deprecated /
    retired / blocked
  * Dependency mapping across assets (uses_model, uses_tool,
    reads_data, served_by, calls_agent, uses_provider, ...)
  * Policy rules — first-priority-wins, technical effects:
      ALLOW / DENY / REQUIRE_APPROVAL / REQUIRE_AUDIT /
      RATE_LIMIT / REQUIRE_REDACTION
  * Runtime enforcement — evaluation at pre-invocation:
      model usage control, tool access control, data access
      control, agent authority enforcement
  * Post-invocation verification — outcome contract
  * Rate limiter (sliding window per (principal, resource, action))
  * Audit trail — every decision, every enforcement
  * Inventory hygiene analysis (technical governance findings):
      unowned asset, unstaged asset, blocked-in-use,
      dependency cycle, orphaned agent, missing provider,
      policy gap, data-class violation
  * Machine-checkable governance invariants
  * In-memory + SQLite stores
  * Phase-27 engine facade
  * Full test suite + manual runner

Doctrine: governance is not a document. Every governance rule
must resolve to a technical enforcement at a runtime decision point.

This is NEW AI-governance-as-enforcement technology. It is NOT a
GRC platform. It is the enforcement-and-audit layer for AI inventory,
policy, and runtime control.

No third-party dependencies.

Run tests:
    python hydra_phase27_ai_governance_enforcement.py
    pytest hydra_phase27_ai_governance_enforcement.py -q
"""
from __future__ import annotations

import json
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


class AuditSink(Protocol):
    def append(self, record: Mapping[str, Any]) -> None: ...


# =============================================================================
# SECTION 2 — DOMAIN ENUMS
# =============================================================================


class AIAssetKind(str, Enum):
    MODEL = "model"
    AGENT = "agent"
    TOOL = "tool"
    DATASET = "dataset"
    PROVIDER = "provider"
    APPLICATION = "application"
    PROMPT = "prompt"


ALL_ASSET_KINDS: Tuple[AIAssetKind, ...] = tuple(AIAssetKind)


class LifecycleStatus(str, Enum):
    DRAFT = "draft"
    STAGED = "staged"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    RETIRED = "retired"
    BLOCKED = "blocked"


_ALLOWED_LIFECYCLE_EDGES: Mapping[
    LifecycleStatus, FrozenSet[LifecycleStatus]
] = {
    LifecycleStatus.DRAFT: frozenset({
        LifecycleStatus.STAGED, LifecycleStatus.BLOCKED,
        LifecycleStatus.RETIRED,
    }),
    LifecycleStatus.STAGED: frozenset({
        LifecycleStatus.APPROVED, LifecycleStatus.DRAFT,
        LifecycleStatus.BLOCKED, LifecycleStatus.RETIRED,
    }),
    LifecycleStatus.APPROVED: frozenset({
        LifecycleStatus.DEPRECATED, LifecycleStatus.BLOCKED,
        LifecycleStatus.RETIRED,
    }),
    LifecycleStatus.DEPRECATED: frozenset({
        LifecycleStatus.RETIRED, LifecycleStatus.BLOCKED,
        LifecycleStatus.APPROVED,
    }),
    LifecycleStatus.RETIRED: frozenset({LifecycleStatus.BLOCKED}),
    LifecycleStatus.BLOCKED: frozenset({
        LifecycleStatus.DRAFT, LifecycleStatus.RETIRED,
    }),
}


class DataClass(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    REGULATED = "regulated"


_DATA_RANK: Mapping[DataClass, int] = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL: 1,
    DataClass.CONFIDENTIAL: 2,
    DataClass.SECRET: 3,
    DataClass.REGULATED: 4,
}


def data_rank(d: DataClass) -> int:
    return _DATA_RANK[d]


class DependencyKind(str, Enum):
    USES_MODEL = "uses_model"
    USES_TOOL = "uses_tool"
    USES_PROVIDER = "uses_provider"
    READS_DATA = "reads_data"
    SERVED_BY = "served_by"
    CALLS_AGENT = "calls_agent"
    DEPLOYS = "deploys"
    PROMPTS_WITH = "prompts_with"


class ActionKind(str, Enum):
    INVOKE = "invoke"
    TRAIN = "train"
    DEPLOY = "deploy"
    READ_DATA = "read_data"
    WRITE_DATA = "write_data"
    CALL_TOOL = "call_tool"
    DELEGATE = "delegate"
    EDIT = "edit"


class PolicyEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_AUDIT = "require_audit"
    RATE_LIMIT = "rate_limit"
    REQUIRE_REDACTION = "require_redaction"


class EnforcementPoint(str, Enum):
    PRE_INVOCATION = "pre_invocation"
    POST_INVOCATION = "post_invocation"


class GovernanceFindingKind(str, Enum):
    UNOWNED_ASSET = "unowned_asset"
    UNSTAGED_ASSET_IN_USE = "unstaged_asset_in_use"
    BLOCKED_ASSET_IN_USE = "blocked_asset_in_use"
    DEPENDENCY_CYCLE = "dependency_cycle"
    ORPHANED_AGENT = "orphaned_agent"
    MISSING_PROVIDER = "missing_provider"
    POLICY_GAP = "policy_gap"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    DATA_CLASS_VIOLATION = "data_class_violation"
    INVALID_LIFECYCLE_TRANSITION = "invalid_lifecycle_transition"
    POST_INVOCATION_VIOLATION = "post_invocation_violation"


@dataclass(frozen=True)
class GovernanceFinding:
    kind: GovernanceFindingKind
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
# SECTION 3 — INVENTORY
# =============================================================================


@dataclass(frozen=True)
class InventoryItem:
    asset_id: str
    kind: AIAssetKind
    name: str
    version: str
    owner: str
    lifecycle: LifecycleStatus
    data_classification: Optional[DataClass] = None
    provider_id: Optional[str] = None
    tags: FrozenSet[str] = frozenset()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.asset_id:
            raise ValueError("asset_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not self.version:
            raise ValueError("version is required")
        if self.kind is AIAssetKind.DATASET \
           and self.data_classification is None:
            raise ValueError(
                "DATASET asset must carry data_classification"
            )


@dataclass(frozen=True)
class DependencyEdge:
    dependent_id: str
    dependency_id: str
    kind: DependencyKind
    at: datetime
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.dependent_id or not self.dependency_id:
            raise ValueError("dependent_id and dependency_id are required")
        if self.dependent_id == self.dependency_id:
            raise ValueError("self-dependencies are not allowed")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


class InventoryGraph:
    def __init__(self) -> None:
        self._items: Dict[str, InventoryItem] = {}
        self._out: Dict[str, List[DependencyEdge]] = {}
        self._in: Dict[str, List[DependencyEdge]] = {}
        self._edges: List[DependencyEdge] = []

    def add(self, item: InventoryItem) -> None:
        if item.asset_id in self._items:
            raise ValueError(f"asset {item.asset_id} already exists")
        self._items[item.asset_id] = item
        self._out.setdefault(item.asset_id, [])
        self._in.setdefault(item.asset_id, [])

    def item(self, asset_id: str) -> InventoryItem:
        i = self._items.get(asset_id)
        if i is None:
            raise KeyError(f"unknown asset {asset_id}")
        return i

    def items(self) -> Tuple[InventoryItem, ...]:
        return tuple(self._items.values())

    def items_of_kind(self, kind: AIAssetKind) -> Tuple[InventoryItem, ...]:
        return tuple(i for i in self._items.values() if i.kind is kind)

    def link(self, edge: DependencyEdge) -> None:
        if edge.dependent_id not in self._items:
            raise KeyError(f"unknown dependent {edge.dependent_id}")
        if edge.dependency_id not in self._items:
            raise KeyError(f"unknown dependency {edge.dependency_id}")
        for existing in self._out[edge.dependent_id]:
            if existing.dependency_id == edge.dependency_id \
               and existing.kind is edge.kind:
                raise ValueError(
                    f"duplicate dependency {edge.dependent_id}"
                    f"->{edge.dependency_id} ({edge.kind.value})"
                )
        if self._would_create_cycle(edge.dependent_id, edge.dependency_id):
            raise ValueError(
                f"dependency {edge.dependent_id}->{edge.dependency_id} "
                f"creates a cycle"
            )
        self._out[edge.dependent_id].append(edge)
        self._in[edge.dependency_id].append(edge)
        self._edges.append(edge)

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
                stack.append(e.dependency_id)
        return False

    def edges(self) -> Tuple[DependencyEdge, ...]:
        return tuple(self._edges)

    def direct_dependencies(
        self, asset_id: str, kind: Optional[DependencyKind] = None,
    ) -> Tuple[DependencyEdge, ...]:
        return tuple(
            e for e in self._out.get(asset_id, ())
            if kind is None or e.kind is kind
        )

    def direct_dependents(
        self, asset_id: str,
    ) -> Tuple[DependencyEdge, ...]:
        return tuple(self._in.get(asset_id, ()))

    def transitive_dependencies(self, asset_id: str) -> Tuple[str, ...]:
        out: List[str] = []
        seen: set = set()
        stack = [asset_id]
        while stack:
            cur = stack.pop()
            for e in self._out.get(cur, ()):
                if e.dependency_id in seen:
                    continue
                seen.add(e.dependency_id)
                out.append(e.dependency_id)
                stack.append(e.dependency_id)
        return tuple(out)

    def transitive_dependents(self, asset_id: str) -> Tuple[str, ...]:
        out: List[str] = []
        seen: set = set()
        stack = [asset_id]
        while stack:
            cur = stack.pop()
            for e in self._in.get(cur, ()):
                if e.dependent_id in seen:
                    continue
                seen.add(e.dependent_id)
                out.append(e.dependent_id)
                stack.append(e.dependent_id)
        return tuple(out)


# =============================================================================
# SECTION 4 — POLICY
# =============================================================================


@dataclass(frozen=True)
class InvocationRequest:
    request_id: str
    principal_id: str
    resource_id: str
    action: ActionKind
    at: datetime
    data_classification: Optional[DataClass] = None
    approved: bool = False
    context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.request_id:
            raise ValueError("request_id is required")
        if not self.principal_id:
            raise ValueError("principal_id is required")
        if not self.resource_id:
            raise ValueError("resource_id is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


PolicyConditionFn = Callable[[InvocationRequest, InventoryGraph], bool]


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    priority: int                 # lower = higher priority; first match wins
    description: str
    effect: PolicyEffect
    principal_kinds: FrozenSet[AIAssetKind] = frozenset()
    resource_kinds: FrozenSet[AIAssetKind] = frozenset()
    action_kinds: FrozenSet[ActionKind] = frozenset()
    resource_tags: FrozenSet[str] = frozenset()
    min_data_class: Optional[DataClass] = None
    max_calls_per_window: Optional[int] = None
    window_seconds: int = 60
    condition: Optional[PolicyConditionFn] = None

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("rule_id is required")
        if not self.description:
            raise ValueError("description is required")
        if self.effect is PolicyEffect.RATE_LIMIT \
           and (self.max_calls_per_window is None
                or self.max_calls_per_window < 1):
            raise ValueError(
                "RATE_LIMIT rule requires max_calls_per_window >= 1"
            )
        if self.window_seconds < 1:
            raise ValueError("window_seconds must be >= 1")

    def matches(
        self, req: InvocationRequest, graph: InventoryGraph,
    ) -> bool:
        try:
            principal = graph.item(req.principal_id)
            resource = graph.item(req.resource_id)
        except KeyError:
            return False

        if self.principal_kinds and principal.kind not in \
                self.principal_kinds:
            return False
        if self.resource_kinds and resource.kind not in self.resource_kinds:
            return False
        if self.action_kinds and req.action not in self.action_kinds:
            return False
        if self.resource_tags:
            if not (self.resource_tags & resource.tags):
                return False
        if self.min_data_class is not None:
            if req.data_classification is None:
                return False
            if data_rank(req.data_classification) < \
               data_rank(self.min_data_class):
                return False
        if self.condition is not None:
            try:
                if not self.condition(req, graph):
                    return False
            except Exception:  # noqa: BLE001
                return False
        return True


class RateLimiter:
    def __init__(self, *, max_history: int = 2000) -> None:
        if max_history < 1:
            raise ValueError("max_history must be >= 1")
        self._history: Dict[
            Tuple[str, str, ActionKind], deque
        ] = {}
        self._max_history = max_history

    def record(
        self, req: InvocationRequest,
    ) -> None:
        key = (req.principal_id, req.resource_id, req.action)
        dq = self._history.setdefault(key, deque(maxlen=self._max_history))
        dq.append(req.at)

    def count_within(
        self, req: InvocationRequest, *, window_seconds: int,
    ) -> int:
        key = (req.principal_id, req.resource_id, req.action)
        dq = self._history.get(key)
        if dq is None:
            return 0
        cutoff = req.at - timedelta(seconds=window_seconds)
        return sum(1 for t in dq if t >= cutoff)


# =============================================================================
# SECTION 5 — DECISION
# =============================================================================


@dataclass(frozen=True)
class EnforcementDecision:
    request_id: str
    effect: PolicyEffect
    allowed: bool
    matched_rule_id: Optional[str]
    rationale: str
    requires_approval: bool
    requires_audit: bool
    requires_redaction: bool
    rate_limited: bool
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class PostInvocationReport:
    request_id: str
    outcome_ok: bool
    violations: Tuple[str, ...]
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


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
class GovernanceSnapshot:
    items: Mapping[str, InventoryItem]
    edges: Tuple[DependencyEdge, ...]
    rules: Tuple[PolicyRule, ...]
    decisions: Tuple[EnforcementDecision, ...]
    findings: Tuple[GovernanceFinding, ...]


@dataclass(frozen=True)
class GovernanceInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[GovernanceSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_approved_requires_owner(
    snap: GovernanceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, item in snap.items.items():
        if item.lifecycle is LifecycleStatus.APPROVED and not item.owner:
            out.append(InvariantViolation(
                invariant_id="gov.approved_requires_owner",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail="APPROVED asset with empty owner",
            ))
    return tuple(out)


def _inv_dataset_requires_data_class(
    snap: GovernanceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, item in snap.items.items():
        if item.kind is AIAssetKind.DATASET \
           and item.data_classification is None:
            out.append(InvariantViolation(
                invariant_id="gov.dataset_requires_data_class",
                severity=InvariantSeverity.HIGH,
                subject_id=aid,
                detail="DATASET without data classification",
            ))
    return tuple(out)


def _inv_rules_priority_unique(
    snap: GovernanceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    seen: Dict[int, str] = {}
    out: List[InvariantViolation] = []
    for r in snap.rules:
        if r.priority in seen:
            out.append(InvariantViolation(
                invariant_id="gov.rules_priority_unique",
                severity=InvariantSeverity.HIGH,
                subject_id=r.rule_id,
                detail=(
                    f"priority {r.priority} already used by "
                    f"{seen[r.priority]}"
                ),
            ))
        else:
            seen[r.priority] = r.rule_id
    return tuple(out)


def _inv_decisions_bounded_severity(
    snap: GovernanceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for d in snap.decisions:
        if d.allowed and d.effect is PolicyEffect.DENY:
            out.append(InvariantViolation(
                invariant_id="gov.decision_consistent",
                severity=InvariantSeverity.CRITICAL,
                subject_id=d.request_id,
                detail="DENY effect marked allowed",
            ))
    return tuple(out)


def _inv_findings_have_valid_severity(
    snap: GovernanceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if not 1 <= f.severity <= 5:
            out.append(InvariantViolation(
                invariant_id="gov.findings_valid_severity",
                severity=InvariantSeverity.LOW,
                subject_id=f.subject_id,
                detail=f"severity {f.severity}",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[GovernanceInvariant, ...] = (
    GovernanceInvariant(
        invariant_id="gov.approved_requires_owner",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_approved_requires_owner,
        description="APPROVED assets must have an owner.",
    ),
    GovernanceInvariant(
        invariant_id="gov.dataset_requires_data_class",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_dataset_requires_data_class,
        description="Datasets must declare data classification.",
    ),
    GovernanceInvariant(
        invariant_id="gov.rules_priority_unique",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_rules_priority_unique,
        description="Policy priorities must be unique.",
    ),
    GovernanceInvariant(
        invariant_id="gov.decision_consistent",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_decisions_bounded_severity,
        description="DENY decisions must not be marked allowed.",
    ),
    GovernanceInvariant(
        invariant_id="gov.findings_valid_severity",
        severity=InvariantSeverity.LOW,
        predicate=_inv_findings_have_valid_severity,
        description="Findings must carry a valid severity.",
    ),
)


def check_invariants(
    snap: GovernanceSnapshot,
    invariants: Iterable[GovernanceInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 7 — STORE
# =============================================================================


@dataclass(frozen=True)
class AssetRecord:
    asset_id: str
    kind: AIAssetKind
    name: str
    version: str
    owner: str
    lifecycle: LifecycleStatus
    data_classification: Optional[DataClass]
    updated_at: datetime


class GovernanceStore(Protocol):
    def put(self, record: AssetRecord) -> None: ...
    def get(self, asset_id: str) -> Optional[AssetRecord]: ...
    def all(self) -> Tuple[AssetRecord, ...]: ...


class InMemoryGovernanceStore:
    def __init__(self) -> None:
        self._data: Dict[str, AssetRecord] = {}

    def put(self, record: AssetRecord) -> None:
        existing = self._data.get(record.asset_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.asset_id] = record

    def get(self, asset_id: str) -> Optional[AssetRecord]:
        return self._data.get(asset_id)

    def all(self) -> Tuple[AssetRecord, ...]:
        return tuple(self._data.values())


class SqliteGovernanceStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gov_assets (
                asset_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                owner TEXT NOT NULL,
                lifecycle TEXT NOT NULL,
                data_classification TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gov_decisions (
                decision_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gov_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: AssetRecord) -> None:
        existing = self.get(record.asset_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO gov_assets
              (asset_id, kind, name, version, owner, lifecycle,
               data_classification, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_id) DO UPDATE SET
              kind=excluded.kind,
              name=excluded.name,
              version=excluded.version,
              owner=excluded.owner,
              lifecycle=excluded.lifecycle,
              data_classification=excluded.data_classification,
              updated_at=excluded.updated_at
            """,
            (
                record.asset_id, record.kind.value, record.name,
                record.version, record.owner, record.lifecycle.value,
                record.data_classification.value
                if record.data_classification else None,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, asset_id: str) -> Optional[AssetRecord]:
        row = self._conn.execute(
            "SELECT kind, name, version, owner, lifecycle, "
            "data_classification, updated_at FROM gov_assets "
            "WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()
        if row is None:
            return None
        return AssetRecord(
            asset_id=asset_id, kind=AIAssetKind(row[0]), name=row[1],
            version=row[2], owner=row[3],
            lifecycle=LifecycleStatus(row[4]),
            data_classification=(
                DataClass(row[5]) if row[5] else None
            ),
            updated_at=datetime.fromisoformat(row[6]),
        )

    def all(self) -> Tuple[AssetRecord, ...]:
        rows = self._conn.execute("SELECT asset_id FROM gov_assets").fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_decision(self, decision_id: str, decision: EnforcementDecision) -> None:
        payload = {
            "decision_id": decision_id,
            "request_id": decision.request_id,
            "effect": decision.effect.value,
            "allowed": decision.allowed,
            "matched_rule_id": decision.matched_rule_id,
            "rationale": decision.rationale,
            "requires_approval": decision.requires_approval,
            "requires_audit": decision.requires_audit,
            "requires_redaction": decision.requires_redaction,
            "rate_limited": decision.rate_limited,
            "at": decision.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO gov_decisions "
            "(decision_id, payload_json) VALUES (?, ?)",
            (decision_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def put_finding(self, finding_id: str, f: GovernanceFinding) -> None:
        payload = {
            "finding_id": finding_id,
            "kind": f.kind.value,
            "subject_id": f.subject_id,
            "detail": f.detail,
            "severity": f.severity,
            "at": f.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO gov_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 8 — ENGINE
# =============================================================================


class AIGovernanceEnforcementEngine:
    """AI governance as enforceable technical control.

    Responsibilities:
      * inventory of AI assets
      * lifecycle state transitions
      * dependency mapping
      * policy registry
      * pre-invocation enforcement (model usage, tool access,
        data access, agent authority)
      * rate limiting
      * post-invocation verification
      * audit trail
      * hygiene findings
    """

    def __init__(
        self,
        *,
        store: Optional[GovernanceStore] = None,
        rate_limiter: Optional[RateLimiter] = None,
        enforce_lifecycle: bool = True,
    ) -> None:
        self._store: GovernanceStore = store or InMemoryGovernanceStore()
        self._graph = InventoryGraph()
        self._rules: List[PolicyRule] = []
        self._limiter = rate_limiter or RateLimiter()
        self._audit: List[EnforcementDecision] = []
        self._findings: List[GovernanceFinding] = []
        self._decisions_by_request: Dict[str, EnforcementDecision] = {}
        self._post_reports: List[PostInvocationReport] = []
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._enforce_lifecycle = enforce_lifecycle
        self._decision_seq = 0

    # ---- inventory -------------------------------------------------------

    def register_asset(self, item: InventoryItem) -> None:
        self._graph.add(item)

    def register_dependency(self, edge: DependencyEdge) -> None:
        self._graph.link(edge)

    def asset(self, asset_id: str) -> InventoryItem:
        return self._graph.item(asset_id)

    def graph(self) -> InventoryGraph:
        return self._graph

    def transition_lifecycle(
        self,
        asset_id: str,
        new_status: LifecycleStatus,
        *,
        at: datetime,
        reason: str = "",
    ) -> InventoryItem:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        item = self._graph.item(asset_id)
        if new_status is item.lifecycle:
            return item
        if self._enforce_lifecycle:
            allowed = _ALLOWED_LIFECYCLE_EDGES.get(
                item.lifecycle, frozenset()
            )
            if new_status not in allowed:
                self._findings.append(GovernanceFinding(
                    kind=GovernanceFindingKind.INVALID_LIFECYCLE_TRANSITION,
                    subject_id=asset_id,
                    detail=(
                        f"{item.lifecycle.value} → {new_status.value} "
                        f"not permitted"
                    ),
                    severity=4, at=at,
                ))
                raise ValueError(
                    f"invalid lifecycle transition "
                    f"{item.lifecycle.value} → {new_status.value}"
                )
        updated = InventoryItem(
            asset_id=item.asset_id, kind=item.kind, name=item.name,
            version=item.version, owner=item.owner,
            lifecycle=new_status,
            data_classification=item.data_classification,
            provider_id=item.provider_id, tags=item.tags,
            metadata=item.metadata,
        )
        # rebuild graph entries atomically (items are immutable)
        new_graph = InventoryGraph()
        for existing in self._graph.items():
            new_graph.add(updated if existing.asset_id == asset_id else existing)
        for e in self._graph.edges():
            new_graph.link(e)
        self._graph = new_graph
        return updated

    # ---- policies --------------------------------------------------------

    def register_rule(self, rule: PolicyRule) -> None:
        if any(r.rule_id == rule.rule_id for r in self._rules):
            raise ValueError(f"rule {rule.rule_id} already registered")
        if any(r.priority == rule.priority for r in self._rules):
            raise ValueError(
                f"rule priority {rule.priority} already used"
            )
        self._rules.append(rule)
        # keep sorted by priority ascending (lower = higher priority)
        self._rules.sort(key=lambda r: (r.priority, r.rule_id))

    def rules(self) -> Tuple[PolicyRule, ...]:
        return tuple(self._rules)

    # ---- enforcement -----------------------------------------------------

    def evaluate(
        self, req: InvocationRequest,
    ) -> EnforcementDecision:
        if req.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        # 1. Blocked resource or blocked principal → deny
        try:
            resource = self._graph.item(req.resource_id)
            principal = self._graph.item(req.principal_id)
        except KeyError:
            return self._record_decision(
                req, effect=PolicyEffect.DENY, allowed=False,
                matched_rule_id=None,
                rationale="unknown principal or resource",
            )

        if resource.lifecycle is LifecycleStatus.BLOCKED:
            return self._record_decision(
                req, effect=PolicyEffect.DENY, allowed=False,
                matched_rule_id=None,
                rationale=f"resource {resource.asset_id} is BLOCKED",
            )
        if principal.lifecycle is LifecycleStatus.BLOCKED:
            return self._record_decision(
                req, effect=PolicyEffect.DENY, allowed=False,
                matched_rule_id=None,
                rationale=f"principal {principal.asset_id} is BLOCKED",
            )

        # 2. First-match-wins by priority
        for rule in self._rules:
            if not rule.matches(req, self._graph):
                continue

            # RATE_LIMIT
            if rule.effect is PolicyEffect.RATE_LIMIT:
                count = self._limiter.count_within(
                    req, window_seconds=rule.window_seconds,
                )
                if count >= (rule.max_calls_per_window or 0):
                    self._findings.append(GovernanceFinding(
                        kind=GovernanceFindingKind.RATE_LIMIT_EXCEEDED,
                        subject_id=req.request_id,
                        detail=(
                            f"{count} calls in {rule.window_seconds}s "
                            f"(max {rule.max_calls_per_window})"
                        ),
                        severity=4, at=req.at,
                    ))
                    return self._record_decision(
                        req, effect=rule.effect, allowed=False,
                        matched_rule_id=rule.rule_id,
                        rationale=(
                            f"rate limit exceeded by rule {rule.rule_id}"
                        ),
                        rate_limited=True,
                    )
                self._limiter.record(req)
                return self._record_decision(
                    req, effect=rule.effect, allowed=True,
                    matched_rule_id=rule.rule_id,
                    rationale=(
                        f"allowed under rate limit {rule.max_calls_per_window}"
                        f"/{rule.window_seconds}s"
                    ),
                )

            # APPROVAL
            if rule.effect is PolicyEffect.REQUIRE_APPROVAL:
                allowed = req.approved
                return self._record_decision(
                    req, effect=rule.effect, allowed=allowed,
                    matched_rule_id=rule.rule_id,
                    requires_approval=True,
                    rationale=(
                        f"approval required by rule {rule.rule_id}; "
                        f"approved={req.approved}"
                    ),
                )

            # AUDIT
            if rule.effect is PolicyEffect.REQUIRE_AUDIT:
                self._limiter.record(req)
                return self._record_decision(
                    req, effect=rule.effect, allowed=True,
                    matched_rule_id=rule.rule_id,
                    requires_audit=True,
                    rationale=f"allowed under audit by {rule.rule_id}",
                )

            # REDACTION
            if rule.effect is PolicyEffect.REQUIRE_REDACTION:
                self._limiter.record(req)
                return self._record_decision(
                    req, effect=rule.effect, allowed=True,
                    matched_rule_id=rule.rule_id,
                    requires_redaction=True,
                    rationale=(
                        f"allowed with redaction under {rule.rule_id}"
                    ),
                )

            # ALLOW / DENY
            allowed = rule.effect is PolicyEffect.ALLOW
            if allowed:
                self._limiter.record(req)
            return self._record_decision(
                req, effect=rule.effect, allowed=allowed,
                matched_rule_id=rule.rule_id,
                rationale=f"matched rule {rule.rule_id}",
            )

        # 3. No match → POLICY_GAP (default deny)
        self._findings.append(GovernanceFinding(
            kind=GovernanceFindingKind.POLICY_GAP,
            subject_id=req.request_id,
            detail=(
                f"no policy matches {req.action.value} "
                f"{req.principal_id}→{req.resource_id}"
            ),
            severity=3, at=req.at,
        ))
        return self._record_decision(
            req, effect=PolicyEffect.DENY, allowed=False,
            matched_rule_id=None,
            rationale="no policy matched (default deny)",
        )

    def _record_decision(
        self,
        req: InvocationRequest,
        *,
        effect: PolicyEffect,
        allowed: bool,
        matched_rule_id: Optional[str],
        rationale: str,
        requires_approval: bool = False,
        requires_audit: bool = False,
        requires_redaction: bool = False,
        rate_limited: bool = False,
    ) -> EnforcementDecision:
        decision = EnforcementDecision(
            request_id=req.request_id,
            effect=effect,
            allowed=allowed,
            matched_rule_id=matched_rule_id,
            rationale=rationale,
            requires_approval=requires_approval,
            requires_audit=requires_audit,
            requires_redaction=requires_redaction,
            rate_limited=rate_limited,
            at=req.at,
        )
        self._audit.append(decision)
        self._decisions_by_request[req.request_id] = decision
        self._decision_seq += 1
        if isinstance(self._store, SqliteGovernanceStore):
            self._store.put_decision(
                f"d-{self._decision_seq:08d}", decision,
            )
        return decision

    def verify_post_invocation(
        self,
        request_id: str,
        *,
        outcome_ok: bool,
        violations: Iterable[str] = (),
        at: datetime,
    ) -> PostInvocationReport:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        report = PostInvocationReport(
            request_id=request_id, outcome_ok=outcome_ok,
            violations=tuple(violations), at=at,
        )
        self._post_reports.append(report)
        if not outcome_ok or report.violations:
            self._findings.append(GovernanceFinding(
                kind=GovernanceFindingKind.POST_INVOCATION_VIOLATION,
                subject_id=request_id,
                detail=(
                    f"outcome_ok={outcome_ok}, "
                    f"violations={list(report.violations)}"
                ),
                severity=4, at=at,
            ))
        return report

    # ---- hygiene analysis ------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[AssetRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        # Retain enforcement/audit findings but regenerate hygiene ones
        self._findings = [
            f for f in self._findings
            if f.kind in (
                GovernanceFindingKind.RATE_LIMIT_EXCEEDED,
                GovernanceFindingKind.POLICY_GAP,
                GovernanceFindingKind.POST_INVOCATION_VIOLATION,
                GovernanceFindingKind.INVALID_LIFECYCLE_TRANSITION,
            )
        ]

        # Hygiene — per-asset
        for item in self._graph.items():
            if not item.owner:
                self._findings.append(GovernanceFinding(
                    kind=GovernanceFindingKind.UNOWNED_ASSET,
                    subject_id=item.asset_id,
                    detail="no owner assigned",
                    severity=4, at=at,
                ))
            if item.lifecycle is LifecycleStatus.BLOCKED \
               and self._graph.direct_dependents(item.asset_id):
                self._findings.append(GovernanceFinding(
                    kind=GovernanceFindingKind.BLOCKED_ASSET_IN_USE,
                    subject_id=item.asset_id,
                    detail=(
                        f"{len(self._graph.direct_dependents(item.asset_id))}"
                        f" dependent(s) still reference a BLOCKED asset"
                    ),
                    severity=5, at=at,
                ))
            if item.lifecycle is LifecycleStatus.DRAFT \
               and self._graph.direct_dependents(item.asset_id):
                self._findings.append(GovernanceFinding(
                    kind=GovernanceFindingKind.UNSTAGED_ASSET_IN_USE,
                    subject_id=item.asset_id,
                    detail="DRAFT asset has dependents",
                    severity=4, at=at,
                ))
            if item.kind is AIAssetKind.MODEL \
               and item.provider_id is not None:
                if item.provider_id not in {
                    x.asset_id for x in self._graph.items()
                }:
                    self._findings.append(GovernanceFinding(
                        kind=GovernanceFindingKind.MISSING_PROVIDER,
                        subject_id=item.asset_id,
                        detail=(
                            f"provider {item.provider_id} not in inventory"
                        ),
                        severity=3, at=at,
                    ))

        # Orphaned agents (no model or tool dependency)
        for item in self._graph.items_of_kind(AIAssetKind.AGENT):
            deps = self._graph.direct_dependencies(item.asset_id)
            has_model = any(
                e.kind is DependencyKind.USES_MODEL for e in deps
            )
            has_tool = any(
                e.kind is DependencyKind.USES_TOOL for e in deps
            )
            if not (has_model or has_tool):
                self._findings.append(GovernanceFinding(
                    kind=GovernanceFindingKind.ORPHANED_AGENT,
                    subject_id=item.asset_id,
                    detail="agent has no model or tool dependency",
                    severity=3, at=at,
                ))

        # Persist
        records: List[AssetRecord] = []
        for item in self._graph.items():
            rec = AssetRecord(
                asset_id=item.asset_id, kind=item.kind,
                name=item.name, version=item.version,
                owner=item.owner, lifecycle=item.lifecycle,
                data_classification=item.data_classification,
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        if isinstance(self._store, SqliteGovernanceStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(
                    f"f-{i:08d}-{f.kind.value}", f,
                )

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def decision(self, request_id: str) -> Optional[EnforcementDecision]:
        return self._decisions_by_request.get(request_id)

    def audit_log(self) -> Tuple[EnforcementDecision, ...]:
        return tuple(self._audit)

    def findings(self) -> Tuple[GovernanceFinding, ...]:
        return tuple(self._findings)

    def findings_by_kind(self) -> Mapping[GovernanceFindingKind, int]:
        out: Dict[GovernanceFindingKind, int] = {
            k: 0 for k in GovernanceFindingKind
        }
        for f in self._findings:
            out[f.kind] += 1
        return out

    def post_invocation_reports(self) -> Tuple[PostInvocationReport, ...]:
        return tuple(self._post_reports)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, asset_id: str) -> Optional[AssetRecord]:
        return self._store.get(asset_id)

    def dependencies_of(self, asset_id: str) -> Tuple[str, ...]:
        return self._graph.transitive_dependencies(asset_id)

    def dependents_of(self, asset_id: str) -> Tuple[str, ...]:
        return self._graph.transitive_dependents(asset_id)

    def snapshot(self) -> GovernanceSnapshot:
        return GovernanceSnapshot(
            items={i.asset_id: i for i in self._graph.items()},
            edges=self._graph.edges(),
            rules=tuple(self._rules),
            decisions=tuple(self._audit),
            findings=tuple(self._findings),
        )


# =============================================================================
# SECTION 9 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


def _asset(
    aid: str, kind: AIAssetKind = AIAssetKind.MODEL, *,
    name: str = "n", version: str = "1.0", owner: str = "team",
    lifecycle: LifecycleStatus = LifecycleStatus.APPROVED,
    data_classification: Optional[DataClass] = None,
    provider_id: Optional[str] = None,
    tags: Iterable[str] = (),
    metadata: Optional[Mapping[str, Any]] = None,
) -> InventoryItem:
    return InventoryItem(
        asset_id=aid, kind=kind, name=name, version=version,
        owner=owner, lifecycle=lifecycle,
        data_classification=data_classification,
        provider_id=provider_id,
        tags=frozenset(tags),
        metadata=dict(metadata or {}),
    )


def _edge(
    dep: str, depn: str, *,
    kind: DependencyKind = DependencyKind.USES_MODEL,
    at: Optional[datetime] = None,
) -> DependencyEdge:
    return DependencyEdge(
        dependent_id=dep, dependency_id=depn,
        kind=kind, at=at or _t0(),
    )


def _req(
    rid: str = "r1", *,
    principal: str = "agent-1", resource: str = "model-1",
    action: ActionKind = ActionKind.INVOKE,
    data_classification: Optional[DataClass] = None,
    approved: bool = False,
    at: Optional[datetime] = None,
) -> InvocationRequest:
    return InvocationRequest(
        request_id=rid, principal_id=principal, resource_id=resource,
        action=action, at=at or _t0(),
        data_classification=data_classification, approved=approved,
    )


# ---- domain ----

def test_asset_requires_id() -> None:
    try:
        InventoryItem(
            asset_id="", kind=AIAssetKind.MODEL, name="n", version="1",
            owner="o", lifecycle=LifecycleStatus.APPROVED,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_asset_dataset_requires_data_class() -> None:
    try:
        InventoryItem(
            asset_id="d", kind=AIAssetKind.DATASET, name="n",
            version="1", owner="o", lifecycle=LifecycleStatus.APPROVED,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_edge_self_rejected() -> None:
    try:
        DependencyEdge(
            dependent_id="a", dependency_id="a",
            kind=DependencyKind.USES_MODEL, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_data_rank_monotonic() -> None:
    assert data_rank(DataClass.PUBLIC) < data_rank(DataClass.INTERNAL)
    assert data_rank(DataClass.SECRET) < data_rank(DataClass.REGULATED)


def test_lifecycle_edges_have_no_blocked_recovery_to_approved() -> None:
    # BLOCKED can only go to DRAFT or RETIRED
    assert LifecycleStatus.APPROVED not in \
        _ALLOWED_LIFECYCLE_EDGES[LifecycleStatus.BLOCKED]


# ---- inventory graph ----

def test_graph_duplicate_asset_rejected() -> None:
    g = InventoryGraph()
    g.add(_asset("a"))
    try:
        g.add(_asset("a"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_duplicate_edge_rejected() -> None:
    g = InventoryGraph()
    g.add(_asset("a", AIAssetKind.AGENT))
    g.add(_asset("b", AIAssetKind.MODEL))
    g.link(_edge("a", "b", kind=DependencyKind.USES_MODEL))
    try:
        g.link(_edge("a", "b", kind=DependencyKind.USES_MODEL))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_cycle_rejected() -> None:
    g = InventoryGraph()
    g.add(_asset("a", AIAssetKind.AGENT))
    g.add(_asset("b", AIAssetKind.AGENT))
    g.add(_asset("c", AIAssetKind.AGENT))
    g.link(_edge("a", "b", kind=DependencyKind.CALLS_AGENT))
    g.link(_edge("b", "c", kind=DependencyKind.CALLS_AGENT))
    try:
        g.link(_edge("c", "a", kind=DependencyKind.CALLS_AGENT))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_graph_transitive_dependencies() -> None:
    g = InventoryGraph()
    g.add(_asset("a", AIAssetKind.AGENT))
    g.add(_asset("b", AIAssetKind.AGENT))
    g.add(_asset("c", AIAssetKind.MODEL))
    g.link(_edge("a", "b", kind=DependencyKind.CALLS_AGENT))
    g.link(_edge("b", "c", kind=DependencyKind.USES_MODEL))
    assert set(g.transitive_dependencies("a")) == {"b", "c"}


def test_graph_transitive_dependents() -> None:
    g = InventoryGraph()
    g.add(_asset("a", AIAssetKind.AGENT))
    g.add(_asset("b", AIAssetKind.AGENT))
    g.add(_asset("c", AIAssetKind.MODEL))
    g.link(_edge("a", "b", kind=DependencyKind.CALLS_AGENT))
    g.link(_edge("b", "c", kind=DependencyKind.USES_MODEL))
    assert set(g.transitive_dependents("c")) == {"a", "b"}


# ---- policy rules ----

def test_rule_requires_id() -> None:
    try:
        PolicyRule(
            rule_id="", priority=1, description="x",
            effect=PolicyEffect.ALLOW,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_rate_limit_rule_requires_max() -> None:
    try:
        PolicyRule(
            rule_id="r", priority=1, description="x",
            effect=PolicyEffect.RATE_LIMIT,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_rule_matches_no_filter() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    r = PolicyRule(
        rule_id="r", priority=1, description="x",
        effect=PolicyEffect.ALLOW,
    )
    assert r.matches(_req(), eng.graph())


def test_rule_matches_principal_kind() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    r = PolicyRule(
        rule_id="r", priority=1, description="x",
        effect=PolicyEffect.ALLOW,
        principal_kinds=frozenset({AIAssetKind.AGENT}),
    )
    assert r.matches(_req(), eng.graph())


def test_rule_rejects_wrong_principal_kind() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    r = PolicyRule(
        rule_id="r", priority=1, description="x",
        effect=PolicyEffect.ALLOW,
        principal_kinds=frozenset({AIAssetKind.APPLICATION}),
    )
    assert not r.matches(_req(), eng.graph())


def test_rule_min_data_class() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("ds", AIAssetKind.DATASET,
                              data_classification=DataClass.CONFIDENTIAL))
    r = PolicyRule(
        rule_id="r", priority=1, description="x",
        effect=PolicyEffect.DENY,
        min_data_class=DataClass.SECRET,
    )
    req = _req(resource="ds", data_classification=DataClass.INTERNAL)
    assert not r.matches(req, eng.graph())


# ---- enforcement engine ----

def test_engine_registers_asset() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("m"))
    assert eng.asset("m").asset_id == "m"


def test_engine_unknown_asset_rejected() -> None:
    eng = AIGovernanceEnforcementEngine()
    try:
        eng.asset("missing")
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_lifecycle_transition_valid() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("m", lifecycle=LifecycleStatus.DRAFT))
    updated = eng.transition_lifecycle(
        "m", LifecycleStatus.STAGED, at=_t0(),
    )
    assert updated.lifecycle is LifecycleStatus.STAGED


def test_engine_lifecycle_transition_invalid() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("m", lifecycle=LifecycleStatus.RETIRED))
    try:
        eng.transition_lifecycle("m", LifecycleStatus.APPROVED, at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_lifecycle_enforcement_can_be_disabled() -> None:
    eng = AIGovernanceEnforcementEngine(enforce_lifecycle=False)
    eng.register_asset(_asset("m", lifecycle=LifecycleStatus.RETIRED))
    updated = eng.transition_lifecycle(
        "m", LifecycleStatus.APPROVED, at=_t0(),
    )
    assert updated.lifecycle is LifecycleStatus.APPROVED


def test_engine_register_duplicate_rule_rejected() -> None:
    eng = AIGovernanceEnforcementEngine()
    r = PolicyRule(
        rule_id="r1", priority=1, description="x",
        effect=PolicyEffect.ALLOW,
    )
    eng.register_rule(r)
    try:
        eng.register_rule(r)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_register_duplicate_priority_rejected() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_rule(PolicyRule(
        rule_id="r1", priority=1, description="x",
        effect=PolicyEffect.ALLOW,
    ))
    try:
        eng.register_rule(PolicyRule(
            rule_id="r2", priority=1, description="y",
            effect=PolicyEffect.DENY,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_allow_decision() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_rule(PolicyRule(
        rule_id="r1", priority=1, description="x",
        effect=PolicyEffect.ALLOW,
    ))
    d = eng.evaluate(_req())
    assert d.allowed
    assert d.effect is PolicyEffect.ALLOW


def test_engine_deny_decision() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_rule(PolicyRule(
        rule_id="r1", priority=1, description="x",
        effect=PolicyEffect.DENY,
    ))
    d = eng.evaluate(_req())
    assert not d.allowed


def test_engine_first_match_by_priority() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_rule(PolicyRule(
        rule_id="deny", priority=1, description="block all",
        effect=PolicyEffect.DENY,
    ))
    eng.register_rule(PolicyRule(
        rule_id="allow", priority=2, description="allow all",
        effect=PolicyEffect.ALLOW,
    ))
    d = eng.evaluate(_req())
    assert not d.allowed
    assert d.matched_rule_id == "deny"


def test_engine_blocked_resource_denied() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset(
        "model-1", lifecycle=LifecycleStatus.BLOCKED,
    ))
    eng.register_rule(PolicyRule(
        rule_id="r", priority=1, description="x",
        effect=PolicyEffect.ALLOW,
    ))
    d = eng.evaluate(_req())
    assert not d.allowed
    assert "BLOCKED" in d.rationale


def test_engine_unknown_principal_denied() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("model-1"))
    d = eng.evaluate(_req(principal="ghost"))
    assert not d.allowed


def test_engine_no_rule_match_is_policy_gap() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    d = eng.evaluate(_req())
    assert not d.allowed
    kinds = {f.kind for f in eng.findings()}
    assert GovernanceFindingKind.POLICY_GAP in kinds


def test_engine_require_approval_blocks_until_approved() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_rule(PolicyRule(
        rule_id="appr", priority=1, description="require approval",
        effect=PolicyEffect.REQUIRE_APPROVAL,
    ))
    d1 = eng.evaluate(_req("r1", approved=False))
    assert not d1.allowed
    assert d1.requires_approval
    d2 = eng.evaluate(_req("r2", approved=True))
    assert d2.allowed


def test_engine_require_audit_allows_and_flags() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_rule(PolicyRule(
        rule_id="audit", priority=1, description="audit",
        effect=PolicyEffect.REQUIRE_AUDIT,
    ))
    d = eng.evaluate(_req())
    assert d.allowed
    assert d.requires_audit


def test_engine_require_redaction_allows_and_flags() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_rule(PolicyRule(
        rule_id="redact", priority=1, description="redact",
        effect=PolicyEffect.REQUIRE_REDACTION,
    ))
    d = eng.evaluate(_req())
    assert d.allowed
    assert d.requires_redaction


def test_engine_rate_limit_first_call_allowed() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_rule(PolicyRule(
        rule_id="rl", priority=1, description="rate limit",
        effect=PolicyEffect.RATE_LIMIT, max_calls_per_window=2,
        window_seconds=60,
    ))
    d = eng.evaluate(_req("r1", at=_t(0)))
    assert d.allowed


def test_engine_rate_limit_exceeded() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_rule(PolicyRule(
        rule_id="rl", priority=1, description="rate limit",
        effect=PolicyEffect.RATE_LIMIT, max_calls_per_window=2,
        window_seconds=60,
    ))
    assert eng.evaluate(_req("r1", at=_t(0))).allowed
    assert eng.evaluate(_req("r2", at=_t(10))).allowed
    d3 = eng.evaluate(_req("r3", at=_t(20)))
    assert not d3.allowed
    assert d3.rate_limited
    kinds = {f.kind for f in eng.findings()}
    assert GovernanceFindingKind.RATE_LIMIT_EXCEEDED in kinds


def test_engine_rate_limit_window_recovers() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_rule(PolicyRule(
        rule_id="rl", priority=1, description="rate limit",
        effect=PolicyEffect.RATE_LIMIT, max_calls_per_window=1,
        window_seconds=60,
    ))
    assert eng.evaluate(_req("r1", at=_t(0))).allowed
    assert not eng.evaluate(_req("r2", at=_t(30))).allowed
    assert eng.evaluate(_req("r3", at=_t(120))).allowed


def test_engine_audit_log_records_all() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_rule(PolicyRule(
        rule_id="r", priority=1, description="x",
        effect=PolicyEffect.ALLOW,
    ))
    eng.evaluate(_req("r1"))
    eng.evaluate(_req("r2"))
    assert len(eng.audit_log()) == 2


def test_engine_post_invocation_success() -> None:
    eng = AIGovernanceEnforcementEngine()
    report = eng.verify_post_invocation(
        "r1", outcome_ok=True, at=_t(10),
    )
    assert report.outcome_ok
    assert not any(
        f.kind is GovernanceFindingKind.POST_INVOCATION_VIOLATION
        for f in eng.findings()
    )


def test_engine_post_invocation_violation() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.verify_post_invocation(
        "r1", outcome_ok=False,
        violations=("data leaked",), at=_t(10),
    )
    kinds = {f.kind for f in eng.findings()}
    assert GovernanceFindingKind.POST_INVOCATION_VIOLATION in kinds


def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = AIGovernanceEnforcementEngine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_unowned_asset_finding() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("a", owner=""))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert GovernanceFindingKind.UNOWNED_ASSET in kinds


def test_engine_blocked_asset_in_use_finding() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset(
        "model-1", lifecycle=LifecycleStatus.BLOCKED,
    ))
    eng.register_dependency(_edge(
        "agent-1", "model-1", kind=DependencyKind.USES_MODEL,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert GovernanceFindingKind.BLOCKED_ASSET_IN_USE in kinds


def test_engine_unstaged_asset_in_use_finding() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset(
        "model-1", lifecycle=LifecycleStatus.DRAFT,
    ))
    eng.register_dependency(_edge(
        "agent-1", "model-1", kind=DependencyKind.USES_MODEL,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert GovernanceFindingKind.UNSTAGED_ASSET_IN_USE in kinds


def test_engine_missing_provider_finding() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("model-1", provider_id="provider-x"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert GovernanceFindingKind.MISSING_PROVIDER in kinds


def test_engine_orphaned_agent_finding() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert GovernanceFindingKind.ORPHANED_AGENT in kinds


def test_engine_no_orphan_when_agent_uses_model() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_dependency(_edge(
        "agent-1", "model-1", kind=DependencyKind.USES_MODEL,
    ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert GovernanceFindingKind.ORPHANED_AGENT not in kinds


def test_engine_findings_by_kind() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.recompute(at=_t0())
    counts = eng.findings_by_kind()
    assert counts[GovernanceFindingKind.ORPHANED_AGENT] >= 1


def test_engine_record_lookup() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("m"))
    eng.recompute(at=_t0())
    rec = eng.record("m")
    assert rec is not None
    assert rec.lifecycle is LifecycleStatus.APPROVED


def test_engine_dependencies_of() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset("model-1", AIAssetKind.MODEL))
    eng.register_dependency(_edge(
        "agent-1", "model-1", kind=DependencyKind.USES_MODEL,
    ))
    assert "model-1" in eng.dependencies_of("agent-1")


def test_engine_data_class_policy_denies() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("agent-1", AIAssetKind.AGENT))
    eng.register_asset(_asset(
        "ds", AIAssetKind.DATASET,
        data_classification=DataClass.SECRET,
    ))
    eng.register_rule(PolicyRule(
        rule_id="block-secret", priority=1,
        description="deny secret data egress",
        effect=PolicyEffect.DENY,
        action_kinds=frozenset({ActionKind.READ_DATA}),
        min_data_class=DataClass.SECRET,
    ))
    eng.register_rule(PolicyRule(
        rule_id="allow-read", priority=2, description="fallback allow",
        effect=PolicyEffect.ALLOW,
    ))
    d_secret = eng.evaluate(_req(
        resource="ds", action=ActionKind.READ_DATA,
        data_classification=DataClass.SECRET,
    ))
    assert not d_secret.allowed
    d_internal = eng.evaluate(_req(
        resource="ds", action=ActionKind.READ_DATA,
        data_classification=DataClass.INTERNAL,
    ))
    assert d_internal.allowed


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = AIGovernanceEnforcementEngine()
    eng.register_asset(_asset("m"))
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_rules_priority_unique() -> None:
    # Bypass register_rule's uniqueness check by mutating internals
    eng = AIGovernanceEnforcementEngine()
    r1 = PolicyRule(
        rule_id="r1", priority=5, description="x",
        effect=PolicyEffect.ALLOW,
    )
    r2 = PolicyRule(
        rule_id="r2", priority=5, description="y",
        effect=PolicyEffect.DENY,
    )
    eng._rules = [r1, r2]
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "gov.rules_priority_unique" for x in v
    )


def test_invariant_deny_marked_allowed() -> None:
    bad = EnforcementDecision(
        request_id="r", effect=PolicyEffect.DENY, allowed=True,
        matched_rule_id=None, rationale="bad",
        requires_approval=False, requires_audit=False,
        requires_redaction=False, rate_limited=False, at=_t0(),
    )
    snap = GovernanceSnapshot(
        items={}, edges=(), rules=(), decisions=(bad,), findings=(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "gov.decision_consistent" for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryGovernanceStore()
    t = _t0()
    s.put(AssetRecord(
        "a", AIAssetKind.MODEL, "n", "1", "o",
        LifecycleStatus.APPROVED, None, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(AssetRecord(
            "a", AIAssetKind.MODEL, "n", "1", "o",
            LifecycleStatus.DRAFT, None, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "gov.db")
    store = SqliteGovernanceStore(db)
    store.put(AssetRecord(
        "a", AIAssetKind.DATASET, "d", "1", "team",
        LifecycleStatus.APPROVED, DataClass.CONFIDENTIAL, _t0(),
    ))
    got = store.get("a")
    assert got is not None
    assert got.kind is AIAssetKind.DATASET
    assert got.data_classification is DataClass.CONFIDENTIAL


def test_sqlite_store_decision_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "gov.db")
    store = SqliteGovernanceStore(db)
    d = EnforcementDecision(
        request_id="r", effect=PolicyEffect.ALLOW, allowed=True,
        matched_rule_id="rule", rationale="x",
        requires_approval=False, requires_audit=False,
        requires_redaction=False, rate_limited=False, at=_t0(),
    )
    store.put_decision("did-1", d)
    row = store._conn.execute(
        "SELECT payload_json FROM gov_decisions WHERE decision_id = 'did-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["effect"] == "allow"


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
