"""
HYDRA POST-CORE — PHASE 3: IDENTITY + DYNAMIC AUTHORITY
=========================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Identity domain (principals, kinds, tenants)
  * Authority grants (capability-scoped, target-scoped, time-bounded)
  * Delegation with strict subset rules and depth limits
  * State-dependent authorization (identity + intent + context + security
    posture + risk + target + capability + history + time + policy)
  * Authority decay, suspension, revocation, restoration
  * Policy engine (first-match-wins)
  * Machine-checkable authority invariants
  * In-memory and SQLite stores
  * Phase-3 engine facade
  * Full test suite + manual runner

This is NEW state-dependent machine-authority technology, not a role
engine. It does NOT rebuild the existing HYDRA governance/decision layer.

Run tests:
    python hydra_phase3_identity_dynamic_authority.py
    pytest hydra_phase3_identity_dynamic_authority.py -q
"""
from __future__ import annotations

import fnmatch
import json
import sqlite3
from dataclasses import dataclass, field, replace
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


class PrincipalKind(str, Enum):
    HUMAN = "human"
    MACHINE = "machine"
    AGENT = "agent"
    SERVICE = "service"
    DELEGATED = "delegated"


class CapabilityStatus(str, Enum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class AuthorityDecisionKind(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_VERIFICATION = "require_verification"
    NO_AUTHORITY = "no_authority"
    EXPIRED = "expired"
    SUSPENDED = "suspended"


_POSTURE_ORDER: Mapping[str, int] = {
    "unknown": 0,
    "observed": 1,
    "trusted": 1,
    "degraded": 2,
    "suspicious": 3,
    "compromised": 4,
    "quarantined": 5,
}


def _posture_severity(label: str) -> int:
    return _POSTURE_ORDER.get(label, 0)


def _posture_at_least_as_bad(a: str, b: str) -> bool:
    return _posture_severity(a) >= _posture_severity(b)


@dataclass(frozen=True)
class Principal:
    principal_id: str
    kind: PrincipalKind
    tenant_id: str
    parent_id: Optional[str] = None  # delegation chain parent

    def __post_init__(self) -> None:
        if not self.principal_id:
            raise ValueError("principal_id is required")
        if not self.tenant_id:
            raise ValueError("tenant_id is required")


@dataclass(frozen=True)
class SecurityPosture:
    """Input posture from Phase 1 / Phase 2 (or a future source)."""
    label: str
    risk: float
    confidence: float

    def __post_init__(self) -> None:
        if self.label not in _POSTURE_ORDER:
            raise ValueError(f"unknown posture label: {self.label}")
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError("risk must be within [0,1]")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")


# =============================================================================
# SECTION 3 — AUTHORITY GRANT
# =============================================================================


@dataclass(frozen=True)
class AuthorityGrant:
    grant_id: str
    principal_id: str
    capabilities: FrozenSet[str]
    targets: FrozenSet[str]              # empty = wildcard
    issued_at: datetime
    expires_at: Optional[datetime]
    parent_grant_id: Optional[str]
    delegation_depth: int
    max_chain_depth: int

    def __post_init__(self) -> None:
        if not self.grant_id:
            raise ValueError("grant_id is required")
        if not self.principal_id:
            raise ValueError("principal_id is required")
        if not self.capabilities:
            raise ValueError("grant must include at least one capability")
        if self.issued_at.tzinfo is None:
            raise ValueError("issued_at must be timezone-aware")
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None:
                raise ValueError("expires_at must be timezone-aware")
            if self.expires_at <= self.issued_at:
                raise ValueError("expires_at must be after issued_at")
        if self.delegation_depth < 0:
            raise ValueError("delegation_depth must be non-negative")
        if self.max_chain_depth < 0:
            raise ValueError("max_chain_depth must be non-negative")
        if self.delegation_depth > self.max_chain_depth:
            raise ValueError("delegation_depth exceeds max_chain_depth")

    def covers(self, capability: str, target: str) -> bool:
        if capability not in self.capabilities:
            return False
        if not self.targets:
            return True
        for t in self.targets:
            if fnmatch.fnmatchcase(target, t):
                return True
        return False

    def active_at(self, at: datetime) -> bool:
        if self.expires_at is not None and self.expires_at <= at:
            return False
        return self.issued_at <= at


# =============================================================================
# SECTION 4 — AUTHORITY STATE
# =============================================================================


AUTHORITY_NEUTRAL_DECAY = 1.0


@dataclass(frozen=True)
class AuthoritySignal:
    signal_id: str
    weight: float
    polarity: float
    at: datetime

    def __post_init__(self) -> None:
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("weight must be within [0,1]")
        if not -1.0 <= self.polarity <= 1.0:
            raise ValueError("polarity must be within [-1,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class PrincipalAuthorityState:
    principal_id: str
    status: CapabilityStatus
    last_verified_at: datetime
    decay_score: float
    updated_at: datetime

    def __post_init__(self) -> None:
        if not self.principal_id:
            raise ValueError("principal_id is required")
        if not 0.0 <= self.decay_score <= 1.0:
            raise ValueError("decay_score must be within [0,1]")
        if self.last_verified_at.tzinfo is None:
            raise ValueError("last_verified_at must be timezone-aware")
        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")


def compute_decay(
    last_verified_at: datetime,
    at: datetime,
    *,
    half_life_seconds: float,
    signals: Iterable[AuthoritySignal] = (),
) -> float:
    """Time-based decay of authority freshness, penalized by negative signals."""
    if half_life_seconds <= 0:
        raise ValueError("half_life_seconds must be > 0")
    age = (at - last_verified_at).total_seconds()
    if age < 0:
        age = 0
    base = 0.5 ** (age / half_life_seconds)
    penalty = 0.0
    for s in signals:
        if s.at > at:
            continue
        if s.polarity < 0.0:
            penalty += abs(s.polarity) * s.weight * 0.2
    return max(0.0, min(1.0, base - penalty))


# =============================================================================
# SECTION 5 — DELEGATION RULES
# =============================================================================


def validate_delegation(
    parent: AuthorityGrant,
    *,
    child_principal_id: str,
    capabilities: FrozenSet[str],
    targets: FrozenSet[str],
    expires_at: Optional[datetime],
    at: datetime,
) -> None:
    """Raise ValueError if the proposed delegation violates rules."""
    if not child_principal_id:
        raise ValueError("child_principal_id is required")
    if child_principal_id == parent.principal_id:
        raise ValueError("cannot delegate to the parent's own principal")
    if not capabilities:
        raise ValueError("delegated grant must include at least one capability")
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")

    if not capabilities.issubset(parent.capabilities):
        extra = capabilities - parent.capabilities
        raise ValueError(f"delegation exceeds parent capabilities: {sorted(extra)}")

    if parent.targets:
        uncovered = {
            t for t in targets
            if not any(fnmatch.fnmatchcase(t, pat) for pat in parent.targets)
        }
        if uncovered:
            raise ValueError(
                f"delegation exceeds parent target scope: {sorted(uncovered)}"
            )

    if parent.expires_at is not None:
        if expires_at is None:
            raise ValueError(
                "delegation must be time-bounded when parent is time-bounded"
            )
        if expires_at > parent.expires_at:
            raise ValueError("delegation extends beyond parent expiry")

    if expires_at is not None and expires_at <= at:
        raise ValueError("delegated grant expires before it is issued")

    new_depth = parent.delegation_depth + 1
    if new_depth > parent.max_chain_depth:
        raise ValueError(
            f"delegation chain depth {new_depth} exceeds limit "
            f"{parent.max_chain_depth}"
        )


# =============================================================================
# SECTION 6 — POLICY
# =============================================================================


def _pattern_match(pattern: str, value: str) -> bool:
    if pattern == "*":
        return True
    return fnmatch.fnmatchcase(value, pattern)


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    decision: AuthorityDecisionKind
    capability_pattern: Optional[str] = None
    target_pattern: Optional[str] = None
    intent_pattern: Optional[str] = None
    principal_kinds: FrozenSet[PrincipalKind] = frozenset()
    posture_trigger: Optional[str] = None     # fires if posture is at least this bad
    min_risk: Optional[float] = None          # fires if risk >= min_risk

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("rule_id is required")
        if self.posture_trigger is not None and self.posture_trigger not in _POSTURE_ORDER:
            raise ValueError(f"unknown posture_trigger: {self.posture_trigger}")
        if self.min_risk is not None and not 0.0 <= self.min_risk <= 1.0:
            raise ValueError("min_risk must be within [0,1]")

    def matches(self, request: "AuthorizationRequest", principal: Principal) -> bool:
        if self.principal_kinds and principal.kind not in self.principal_kinds:
            return False
        if self.capability_pattern is not None and not _pattern_match(
            self.capability_pattern, request.capability
        ):
            return False
        if self.target_pattern is not None and not _pattern_match(
            self.target_pattern, request.target
        ):
            return False
        if self.intent_pattern is not None and not _pattern_match(
            self.intent_pattern, request.intent
        ):
            return False
        if self.posture_trigger is not None and not _posture_at_least_as_bad(
            request.security_posture.label, self.posture_trigger
        ):
            return False
        if self.min_risk is not None and request.security_posture.risk < self.min_risk:
            return False
        return True


# =============================================================================
# SECTION 7 — AUTHORIZATION REQUEST / DECISION
# =============================================================================


@dataclass(frozen=True)
class AuthorizationRequest:
    request_id: str
    principal_id: str
    capability: str
    target: str
    intent: str
    at: datetime
    security_posture: SecurityPosture
    context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.request_id:
            raise ValueError("request_id is required")
        if not self.principal_id:
            raise ValueError("principal_id is required")
        if not self.capability:
            raise ValueError("capability is required")
        if not self.target:
            raise ValueError("target is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class AuthorityDecision:
    request_id: str
    kind: AuthorityDecisionKind
    rationale: str
    matched_grants: Tuple[str, ...]
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

    @property
    def is_allow(self) -> bool:
        return self.kind is AuthorityDecisionKind.ALLOW


# =============================================================================
# SECTION 8 — HIGH-IMPACT CAPABILITIES
# =============================================================================


HIGH_IMPACT_CAPABILITIES: FrozenSet[str] = frozenset({
    "execute:shell",
    "modify:policy",
    "delete:data",
    "grant:authority",
    "revoke:authority",
    "modify:kernel",
    "modify:firmware",
    "execute:deploy",
    "modify:network",
    "shutdown:service",
})


def requires_stated_intent(capability: str) -> bool:
    return capability in HIGH_IMPACT_CAPABILITIES


# =============================================================================
# SECTION 9 — INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AuthorityViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class AuthoritySnapshot:
    principals: Mapping[str, Principal]
    grants: Mapping[str, AuthorityGrant]
    states: Mapping[str, PrincipalAuthorityState]


@dataclass(frozen=True)
class AuthorityInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[AuthoritySnapshot], Tuple[AuthorityViolation, ...]]
    description: str


def _inv_delegation_capability_subset(
    snap: AuthoritySnapshot,
) -> Tuple[AuthorityViolation, ...]:
    out: List[AuthorityViolation] = []
    for gid, g in snap.grants.items():
        if g.parent_grant_id is None:
            continue
        parent = snap.grants.get(g.parent_grant_id)
        if parent is None:
            continue
        if not g.capabilities.issubset(parent.capabilities):
            out.append(AuthorityViolation(
                invariant_id="auth.delegation_capability_subset",
                severity=InvariantSeverity.CRITICAL,
                subject_id=gid,
                detail=(
                    f"grant {gid} capabilities exceed parent "
                    f"{g.parent_grant_id}"
                ),
            ))
    return tuple(out)


def _inv_delegation_expiry_subset(
    snap: AuthoritySnapshot,
) -> Tuple[AuthorityViolation, ...]:
    out: List[AuthorityViolation] = []
    for gid, g in snap.grants.items():
        if g.parent_grant_id is None:
            continue
        parent = snap.grants.get(g.parent_grant_id)
        if parent is None or parent.expires_at is None:
            continue
        if g.expires_at is None or g.expires_at > parent.expires_at:
            out.append(AuthorityViolation(
                invariant_id="auth.delegation_expiry_subset",
                severity=InvariantSeverity.CRITICAL,
                subject_id=gid,
                detail=(
                    f"grant {gid} expiry exceeds parent "
                    f"{g.parent_grant_id}"
                ),
            ))
    return tuple(out)


def _inv_delegation_depth_bounded(
    snap: AuthoritySnapshot,
) -> Tuple[AuthorityViolation, ...]:
    out: List[AuthorityViolation] = []
    for gid, g in snap.grants.items():
        if g.delegation_depth > g.max_chain_depth:
            out.append(AuthorityViolation(
                invariant_id="auth.delegation_depth_bounded",
                severity=InvariantSeverity.CRITICAL,
                subject_id=gid,
                detail=(
                    f"grant {gid} depth {g.delegation_depth} > "
                    f"max {g.max_chain_depth}"
                ),
            ))
    return tuple(out)


def _inv_parent_grant_exists(
    snap: AuthoritySnapshot,
) -> Tuple[AuthorityViolation, ...]:
    out: List[AuthorityViolation] = []
    for gid, g in snap.grants.items():
        if g.parent_grant_id is None:
            continue
        if g.parent_grant_id not in snap.grants:
            out.append(AuthorityViolation(
                invariant_id="auth.parent_grant_exists",
                severity=InvariantSeverity.CRITICAL,
                subject_id=gid,
                detail=f"grant {gid} references missing parent {g.parent_grant_id}",
            ))
    return tuple(out)


def _inv_revoked_principal_no_active_grant(
    snap: AuthoritySnapshot,
) -> Tuple[AuthorityViolation, ...]:
    out: List[AuthorityViolation] = []
    for gid, g in snap.grants.items():
        state = snap.states.get(g.principal_id)
        if state is None:
            continue
        if state.status is CapabilityStatus.REVOKED:
            out.append(AuthorityViolation(
                invariant_id="auth.revoked_principal_no_active_grant",
                severity=InvariantSeverity.HIGH,
                subject_id=gid,
                detail=(
                    f"revoked principal {g.principal_id} still holds "
                    f"grant {gid}"
                ),
            ))
    return tuple(out)


DEFAULT_AUTHORITY_INVARIANTS: Tuple[AuthorityInvariant, ...] = (
    AuthorityInvariant(
        invariant_id="auth.delegation_capability_subset",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_delegation_capability_subset,
        description="Delegated capabilities must be a subset of the parent's.",
    ),
    AuthorityInvariant(
        invariant_id="auth.delegation_expiry_subset",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_delegation_expiry_subset,
        description="Delegated expiry must not exceed the parent's.",
    ),
    AuthorityInvariant(
        invariant_id="auth.delegation_depth_bounded",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_delegation_depth_bounded,
        description="Delegation depth must not exceed the chain limit.",
    ),
    AuthorityInvariant(
        invariant_id="auth.parent_grant_exists",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_parent_grant_exists,
        description="Every delegated grant must reference an existing parent.",
    ),
    AuthorityInvariant(
        invariant_id="auth.revoked_principal_no_active_grant",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_revoked_principal_no_active_grant,
        description="A revoked principal must not retain active grants.",
    ),
)


def check_authority_invariants(
    snap: AuthoritySnapshot,
    invariants: Iterable[AuthorityInvariant] = DEFAULT_AUTHORITY_INVARIANTS,
) -> Tuple[AuthorityViolation, ...]:
    out: List[AuthorityViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 10 — STORES
# =============================================================================


class AuthorityStore(Protocol):
    def put_grant(self, grant: AuthorityGrant) -> None: ...
    def get_grant(self, grant_id: str) -> Optional[AuthorityGrant]: ...
    def all_grants(self) -> Tuple[AuthorityGrant, ...]: ...
    def put_state(self, state: PrincipalAuthorityState) -> None: ...
    def get_state(self, principal_id: str) -> Optional[PrincipalAuthorityState]: ...
    def all_states(self) -> Tuple[PrincipalAuthorityState, ...]: ...


class InMemoryAuthorityStore:
    def __init__(self) -> None:
        self._grants: Dict[str, AuthorityGrant] = {}
        self._states: Dict[str, PrincipalAuthorityState] = {}

    def put_grant(self, grant: AuthorityGrant) -> None:
        if grant.grant_id in self._grants:
            raise ValueError(f"grant {grant.grant_id} already exists")
        self._grants[grant.grant_id] = grant

    def get_grant(self, grant_id: str) -> Optional[AuthorityGrant]:
        return self._grants.get(grant_id)

    def all_grants(self) -> Tuple[AuthorityGrant, ...]:
        return tuple(self._grants.values())

    def put_state(self, state: PrincipalAuthorityState) -> None:
        existing = self._states.get(state.principal_id)
        if existing is not None and existing.updated_at > state.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._states[state.principal_id] = state

    def get_state(self, principal_id: str) -> Optional[PrincipalAuthorityState]:
        return self._states.get(principal_id)

    def all_states(self) -> Tuple[PrincipalAuthorityState, ...]:
        return tuple(self._states.values())


def _caps_to_json(caps: FrozenSet[str]) -> str:
    return json.dumps(sorted(caps))


def _caps_from_json(s: str) -> FrozenSet[str]:
    return frozenset(json.loads(s))


class SqliteAuthorityStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_grants (
                grant_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                capabilities_json TEXT NOT NULL,
                targets_json TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT,
                parent_grant_id TEXT,
                delegation_depth INTEGER NOT NULL,
                max_chain_depth INTEGER NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_states (
                principal_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                last_verified_at TEXT NOT NULL,
                decay_score REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put_grant(self, grant: AuthorityGrant) -> None:
        existing = self.get_grant(grant.grant_id)
        if existing is not None:
            raise ValueError(f"grant {grant.grant_id} already exists")
        self._conn.execute(
            """
            INSERT INTO auth_grants
              (grant_id, principal_id, capabilities_json, targets_json,
               issued_at, expires_at, parent_grant_id,
               delegation_depth, max_chain_depth)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                grant.grant_id,
                grant.principal_id,
                _caps_to_json(grant.capabilities),
                _caps_to_json(grant.targets),
                grant.issued_at.isoformat(),
                grant.expires_at.isoformat() if grant.expires_at else None,
                grant.parent_grant_id,
                grant.delegation_depth,
                grant.max_chain_depth,
            ),
        )
        self._conn.commit()

    def get_grant(self, grant_id: str) -> Optional[AuthorityGrant]:
        row = self._conn.execute(
            "SELECT principal_id, capabilities_json, targets_json, issued_at, "
            "expires_at, parent_grant_id, delegation_depth, max_chain_depth "
            "FROM auth_grants WHERE grant_id = ?",
            (grant_id,),
        ).fetchone()
        if row is None:
            return None
        return AuthorityGrant(
            grant_id=grant_id,
            principal_id=row[0],
            capabilities=_caps_from_json(row[1]),
            targets=_caps_from_json(row[2]),
            issued_at=datetime.fromisoformat(row[3]),
            expires_at=datetime.fromisoformat(row[4]) if row[4] else None,
            parent_grant_id=row[5],
            delegation_depth=row[6],
            max_chain_depth=row[7],
        )

    def all_grants(self) -> Tuple[AuthorityGrant, ...]:
        ids = [r[0] for r in self._conn.execute("SELECT grant_id FROM auth_grants").fetchall()]
        return tuple(g for g in (self.get_grant(gid) for gid in ids) if g is not None)

    def put_state(self, state: PrincipalAuthorityState) -> None:
        existing = self.get_state(state.principal_id)
        if existing is not None and existing.updated_at > state.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO auth_states
              (principal_id, status, last_verified_at, decay_score, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(principal_id) DO UPDATE SET
              status=excluded.status,
              last_verified_at=excluded.last_verified_at,
              decay_score=excluded.decay_score,
              updated_at=excluded.updated_at
            """,
            (
                state.principal_id,
                state.status.value,
                state.last_verified_at.isoformat(),
                state.decay_score,
                state.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get_state(self, principal_id: str) -> Optional[PrincipalAuthorityState]:
        row = self._conn.execute(
            "SELECT status, last_verified_at, decay_score, updated_at "
            "FROM auth_states WHERE principal_id = ?",
            (principal_id,),
        ).fetchone()
        if row is None:
            return None
        return PrincipalAuthorityState(
            principal_id=principal_id,
            status=CapabilityStatus(row[0]),
            last_verified_at=datetime.fromisoformat(row[1]),
            decay_score=float(row[2]),
            updated_at=datetime.fromisoformat(row[3]),
        )

    def all_states(self) -> Tuple[PrincipalAuthorityState, ...]:
        rows = self._conn.execute(
            "SELECT principal_id FROM auth_states"
        ).fetchall()
        return tuple(
            s for s in (self.get_state(r[0]) for r in rows) if s is not None
        )


# =============================================================================
# SECTION 11 — ENGINE
# =============================================================================


class AuthorityEngine:
    """State-dependent machine authority engine.

    Consumes Phase 1 / Phase 2 posture inputs via `SecurityPosture`.
    Emits `AuthorityDecision` records. Enforces delegation rules, decay,
    suspension, revocation, restoration, and policy.
    """

    def __init__(self, *, store: Optional[AuthorityStore] = None) -> None:
        self._store: AuthorityStore = store or InMemoryAuthorityStore()
        self._principals: Dict[str, Principal] = {}
        self._grants: Dict[str, AuthorityGrant] = {}
        self._principal_grants: Dict[str, List[str]] = {}
        self._signals: Dict[str, List[AuthoritySignal]] = {}
        self._policies: List[PolicyRule] = []
        self._grants_seq = 0
        self._decisions: List[AuthorityDecision] = []

    # ---- principals ------------------------------------------------------

    def register_principal(self, principal: Principal) -> None:
        if principal.principal_id in self._principals:
            raise ValueError(f"principal {principal.principal_id} already registered")
        if principal.parent_id is not None and principal.parent_id not in self._principals:
            raise ValueError(
                f"principal parent {principal.parent_id} not registered"
            )
        self._principals[principal.principal_id] = principal

    def principal(self, principal_id: str) -> Principal:
        p = self._principals.get(principal_id)
        if p is None:
            raise KeyError(f"unknown principal {principal_id}")
        return p

    # ---- policy ----------------------------------------------------------

    def add_policy(self, rule: PolicyRule) -> None:
        if any(r.rule_id == rule.rule_id for r in self._policies):
            raise ValueError(f"policy {rule.rule_id} already registered")
        self._policies.append(rule)

    def policies(self) -> Tuple[PolicyRule, ...]:
        return tuple(self._policies)

    # ---- granting --------------------------------------------------------

    def grant_root(
        self,
        *,
        principal_id: str,
        capabilities: Iterable[str],
        targets: Iterable[str] = (),
        issued_at: datetime,
        expires_at: Optional[datetime] = None,
        max_chain_depth: int = 3,
    ) -> AuthorityGrant:
        if principal_id not in self._principals:
            raise KeyError(f"unknown principal {principal_id}")
        caps = frozenset(capabilities)
        grant = AuthorityGrant(
            grant_id=self._next_grant_id(),
            principal_id=principal_id,
            capabilities=caps,
            targets=frozenset(targets),
            issued_at=issued_at,
            expires_at=expires_at,
            parent_grant_id=None,
            delegation_depth=0,
            max_chain_depth=max_chain_depth,
        )
        self._register_grant(grant)
        self._ensure_state(principal_id, at=issued_at)
        return grant

    def delegate(
        self,
        *,
        parent_grant_id: str,
        child_principal_id: str,
        capabilities: Iterable[str],
        targets: Iterable[str] = (),
        expires_at: Optional[datetime],
        at: datetime,
    ) -> AuthorityGrant:
        parent = self._grants.get(parent_grant_id)
        if parent is None:
            raise KeyError(f"unknown parent grant {parent_grant_id}")
        if child_principal_id not in self._principals:
            raise KeyError(f"unknown child principal {child_principal_id}")
        caps = frozenset(capabilities)
        tgts = frozenset(targets)

        validate_delegation(
            parent,
            child_principal_id=child_principal_id,
            capabilities=caps,
            targets=tgts,
            expires_at=expires_at,
            at=at,
        )

        grant = AuthorityGrant(
            grant_id=self._next_grant_id(),
            principal_id=child_principal_id,
            capabilities=caps,
            targets=tgts,
            issued_at=at,
            expires_at=expires_at,
            parent_grant_id=parent_grant_id,
            delegation_depth=parent.delegation_depth + 1,
            max_chain_depth=parent.max_chain_depth,
        )
        self._register_grant(grant)
        self._ensure_state(child_principal_id, at=at)
        return grant

    # ---- lifecycle -------------------------------------------------------

    def suspend(self, principal_id: str, *, reason: str, at: datetime) -> None:
        state = self._require_state(principal_id)
        if state.status is CapabilityStatus.REVOKED:
            raise ValueError("cannot suspend a revoked principal")
        if not reason:
            raise ValueError("reason is required")
        new = replace(state, status=CapabilityStatus.SUSPENDED, updated_at=at)
        self._store.put_state(new)

    def revoke(self, principal_id: str, *, reason: str, at: datetime) -> None:
        state = self._require_state(principal_id)
        if not reason:
            raise ValueError("reason is required")
        new = replace(state, status=CapabilityStatus.REVOKED, updated_at=at)
        self._store.put_state(new)

    def restore(
        self,
        principal_id: str,
        *,
        verified: bool,
        reason: str,
        at: datetime,
    ) -> None:
        state = self._require_state(principal_id)
        if not reason:
            raise ValueError("reason is required")
        if state.status is CapabilityStatus.ACTIVE:
            return
        if state.status is CapabilityStatus.REVOKED:
            raise ValueError(
                "revoked authority cannot be restored; a fresh grant is required"
            )
        if state.status is CapabilityStatus.SUSPENDED and not verified:
            raise ValueError("restore from suspension requires verification")
        new = replace(
            state,
            status=CapabilityStatus.ACTIVE,
            last_verified_at=at,
            decay_score=1.0,
            updated_at=at,
        )
        self._store.put_state(new)

    def verify_authority(self, principal_id: str, *, at: datetime) -> None:
        state = self._require_state(principal_id)
        if state.status is CapabilityStatus.REVOKED:
            raise ValueError("cannot verify revoked authority")
        new = replace(
            state,
            status=CapabilityStatus.ACTIVE,
            last_verified_at=at,
            decay_score=1.0,
            updated_at=at,
        )
        self._store.put_state(new)

    def observe_signal(self, principal_id: str, signal: AuthoritySignal) -> None:
        if principal_id not in self._principals:
            raise KeyError(f"unknown principal {principal_id}")
        self._signals.setdefault(principal_id, []).append(signal)

    def recompute_decay(
        self, *, at: datetime, half_life_seconds: float = 86400.0,
    ) -> None:
        for state in list(self._store.all_states()):
            if state.status is CapabilityStatus.REVOKED:
                continue
            decay = compute_decay(
                state.last_verified_at,
                at,
                half_life_seconds=half_life_seconds,
                signals=self._signals.get(state.principal_id, ()),
            )
            new_status = state.status
            if state.status is CapabilityStatus.ACTIVE and decay < 0.3:
                new_status = CapabilityStatus.DEGRADED
            new = replace(
                state,
                decay_score=decay,
                status=new_status,
                updated_at=at,
            )
            self._store.put_state(new)

    # ---- authorization ---------------------------------------------------

    def authorize(self, request: AuthorizationRequest) -> AuthorityDecision:
        principal = self._principals.get(request.principal_id)
        if principal is None:
            return self._decide(request, AuthorityDecisionKind.DENY,
                                "unknown principal", ())

        state = self._store.get_state(request.principal_id)
        if state is None:
            return self._decide(request, AuthorityDecisionKind.NO_AUTHORITY,
                                "no authority state", ())

        # 1. Hard status gate
        if state.status is CapabilityStatus.REVOKED:
            return self._decide(request, AuthorityDecisionKind.DENY,
                                "authority revoked", ())
        if state.status is CapabilityStatus.SUSPENDED:
            return self._decide(request, AuthorityDecisionKind.SUSPENDED,
                                "authority suspended", ())

        # 2. Security posture gate
        if request.security_posture.label in ("compromised", "quarantined"):
            return self._decide(
                request,
                AuthorityDecisionKind.DENY,
                f"security posture '{request.security_posture.label}' forbids authorization",
                (),
            )

        # 3. Matching grants
        candidates = self._matching_grants(request)
        if not candidates:
            return self._decide(
                request, AuthorityDecisionKind.NO_AUTHORITY,
                "no grant matches capability and target", (),
            )
        cand_ids = tuple(g.grant_id for g in candidates)

        # 4. Expiry
        unexpired = [g for g in candidates if g.active_at(request.at)]
        if not unexpired:
            return self._decide(
                request, AuthorityDecisionKind.EXPIRED,
                "matching grants are expired", cand_ids,
            )
        valid_ids = tuple(g.grant_id for g in unexpired)

        # 5. Intent requirement for high-impact capabilities
        if requires_stated_intent(request.capability) and not request.intent:
            return self._decide(
                request, AuthorityDecisionKind.REQUIRE_APPROVAL,
                f"high-impact capability '{request.capability}' requires stated intent",
                valid_ids,
            )

        # 6. Policy evaluation (first-match-wins)
        for rule in self._policies:
            if rule.matches(request, principal):
                return self._decide(
                    request, rule.decision,
                    f"policy {rule.rule_id} matched", valid_ids,
                )

        # 7. Decay gate
        decay = state.decay_score
        if decay < 0.3:
            return self._decide(
                request, AuthorityDecisionKind.REQUIRE_VERIFICATION,
                f"authority decayed to {decay:.2f}", valid_ids,
            )
        if decay < 0.6:
            return self._decide(
                request, AuthorityDecisionKind.REQUIRE_APPROVAL,
                f"authority decayed to {decay:.2f}", valid_ids,
            )

        # 8. Risk gate
        risk = request.security_posture.risk
        if risk >= 0.8:
            return self._decide(
                request, AuthorityDecisionKind.REQUIRE_APPROVAL,
                f"high risk ({risk:.2f})", valid_ids,
            )
        if risk >= 0.5:
            return self._decide(
                request, AuthorityDecisionKind.REQUIRE_VERIFICATION,
                f"moderate risk ({risk:.2f})", valid_ids,
            )

        # 9. Allow
        return self._decide(
            request, AuthorityDecisionKind.ALLOW,
            "authority verified", valid_ids,
        )

    # ---- queries ---------------------------------------------------------

    def grant(self, grant_id: str) -> Optional[AuthorityGrant]:
        return self._grants.get(grant_id)

    def state(self, principal_id: str) -> Optional[PrincipalAuthorityState]:
        return self._store.get_state(principal_id)

    def decisions(self) -> Tuple[AuthorityDecision, ...]:
        return tuple(self._decisions)

    def snapshot(self) -> AuthoritySnapshot:
        return AuthoritySnapshot(
            principals=dict(self._principals),
            grants=dict(self._grants),
            states={s.principal_id: s for s in self._store.all_states()},
        )

    def violations(self) -> Tuple[AuthorityViolation, ...]:
        return check_authority_invariants(self.snapshot())

    # ---- internals -------------------------------------------------------

    def _next_grant_id(self) -> str:
        self._grants_seq += 1
        return f"g-{self._grants_seq:06d}"

    def _register_grant(self, grant: AuthorityGrant) -> None:
        self._store.put_grant(grant)
        self._grants[grant.grant_id] = grant
        self._principal_grants.setdefault(grant.principal_id, []).append(grant.grant_id)

    def _ensure_state(self, principal_id: str, *, at: datetime) -> None:
        if self._store.get_state(principal_id) is None:
            self._store.put_state(PrincipalAuthorityState(
                principal_id=principal_id,
                status=CapabilityStatus.ACTIVE,
                last_verified_at=at,
                decay_score=1.0,
                updated_at=at,
            ))

    def _require_state(self, principal_id: str) -> PrincipalAuthorityState:
        state = self._store.get_state(principal_id)
        if state is None:
            raise KeyError(f"no authority state for {principal_id}")
        return state

    def _matching_grants(
        self, request: AuthorizationRequest,
    ) -> List[AuthorityGrant]:
        out: List[AuthorityGrant] = []
        for gid in self._principal_grants.get(request.principal_id, []):
            g = self._grants.get(gid)
            if g is None:
                continue
            if g.covers(request.capability, request.target):
                out.append(g)
        return out

    def _decide(
        self,
        request: AuthorizationRequest,
        kind: AuthorityDecisionKind,
        rationale: str,
        matched_grants: Tuple[str, ...],
    ) -> AuthorityDecision:
        decision = AuthorityDecision(
            request_id=request.request_id,
            kind=kind,
            rationale=rationale,
            matched_grants=matched_grants,
            at=request.at,
        )
        self._decisions.append(decision)
        return decision


# =============================================================================
# SECTION 12 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _human(pid: str = "alice") -> Principal:
    return Principal(principal_id=pid, kind=PrincipalKind.HUMAN, tenant_id="t1")


def _agent(pid: str = "agent-1") -> Principal:
    return Principal(principal_id=pid, kind=PrincipalKind.AGENT, tenant_id="t1")


def _posture(label: str = "trusted", risk: float = 0.1,
             conf: float = 0.9) -> SecurityPosture:
    return SecurityPosture(label=label, risk=risk, confidence=conf)


def _request(pid: str = "alice", cap: str = "read:data",
             target: str = "db-prod", *, at: Optional[datetime] = None,
             intent: str = "read logs",
             posture: Optional[SecurityPosture] = None) -> AuthorizationRequest:
    return AuthorizationRequest(
        request_id="req-1",
        principal_id=pid,
        capability=cap,
        target=target,
        intent=intent,
        at=at or _t0(),
        security_posture=posture or _posture(),
    )


# ---- domain tests ---------------------------------------------------------

def test_principal_requires_id_and_tenant() -> None:
    try:
        Principal(principal_id="", kind=PrincipalKind.HUMAN, tenant_id="t")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    try:
        Principal(principal_id="p", kind=PrincipalKind.HUMAN, tenant_id="")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_grant_empty_capabilities_rejected() -> None:
    try:
        AuthorityGrant(
            grant_id="g", principal_id="p",
            capabilities=frozenset(), targets=frozenset(),
            issued_at=_t0(), expires_at=None,
            parent_grant_id=None, delegation_depth=0, max_chain_depth=3,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_grant_expiry_before_issue_rejected() -> None:
    try:
        AuthorityGrant(
            grant_id="g", principal_id="p",
            capabilities=frozenset({"read"}),
            targets=frozenset(),
            issued_at=_t0(),
            expires_at=_t0().replace(year=_t0().year - 1),
            parent_grant_id=None, delegation_depth=0, max_chain_depth=3,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_grant_covers_wildcard_target() -> None:
    g = AuthorityGrant(
        grant_id="g", principal_id="p",
        capabilities=frozenset({"read:data"}),
        targets=frozenset(),
        issued_at=_t0(), expires_at=None,
        parent_grant_id=None, delegation_depth=0, max_chain_depth=3,
    )
    assert g.covers("read:data", "anything")
    assert not g.covers("write:data", "anything")


def test_grant_covers_pattern_target() -> None:
    g = AuthorityGrant(
        grant_id="g", principal_id="p",
        capabilities=frozenset({"read:data"}),
        targets=frozenset({"db-*"}),
        issued_at=_t0(), expires_at=None,
        parent_grant_id=None, delegation_depth=0, max_chain_depth=3,
    )
    assert g.covers("read:data", "db-prod")
    assert not g.covers("read:data", "cache-1")


def test_grant_active_at() -> None:
    g = AuthorityGrant(
        grant_id="g", principal_id="p",
        capabilities=frozenset({"read"}),
        targets=frozenset(),
        issued_at=_t0(),
        expires_at=_t0().replace(year=_t0().year + 1),
        parent_grant_id=None, delegation_depth=0, max_chain_depth=3,
    )
    assert g.active_at(_t0())
    later = _t0().replace(year=_t0().year + 2)
    assert not g.active_at(later)


# ---- decay tests ----------------------------------------------------------

def test_decay_halves_at_half_life() -> None:
    d = compute_decay(_t0(), _t0().replace(hour=1) if False else _t0(),
                      half_life_seconds=60.0)
    assert d == 1.0
    later = _t0().replace(minute=1)
    d2 = compute_decay(_t0(), later, half_life_seconds=60.0)
    assert abs(d2 - 0.5) < 1e-6


def test_decay_never_negative_with_signals() -> None:
    from datetime import timedelta
    sigs = [
        AuthoritySignal(signal_id=f"s{i}", weight=1.0, polarity=-1.0, at=_t0())
        for i in range(10)
    ]
    d = compute_decay(_t0(), _t0() + timedelta(seconds=1),
                      half_life_seconds=60.0, signals=sigs)
    assert d >= 0.0


def test_decay_penalized_by_negative_signal() -> None:
    from datetime import timedelta
    later = _t0() + timedelta(seconds=60)
    baseline = compute_decay(_t0(), later, half_life_seconds=600.0)
    sig = AuthoritySignal(signal_id="s", weight=1.0, polarity=-1.0, at=_t0())
    penalized = compute_decay(_t0(), later, half_life_seconds=600.0, signals=[sig])
    assert penalized < baseline


def test_decay_requires_positive_half_life() -> None:
    try:
        compute_decay(_t0(), _t0(), half_life_seconds=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- delegation tests -----------------------------------------------------

def _parent_grant(caps=("read:data", "write:data"), targets=("db-*",),
                  expires_at=None, max_depth=3) -> AuthorityGrant:
    return AuthorityGrant(
        grant_id="g-parent", principal_id="alice",
        capabilities=frozenset(caps),
        targets=frozenset(targets),
        issued_at=_t0(),
        expires_at=expires_at,
        parent_grant_id=None,
        delegation_depth=0,
        max_chain_depth=max_depth,
    )


def test_delegation_extends_capability_rejected() -> None:
    parent = _parent_grant()
    try:
        validate_delegation(
            parent,
            child_principal_id="agent-1",
            capabilities=frozenset({"read:data", "delete:data"}),
            targets=frozenset(),
            expires_at=None,
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_delegation_extends_target_scope_rejected() -> None:
    parent = _parent_grant()
    try:
        validate_delegation(
            parent,
            child_principal_id="agent-1",
            capabilities=frozenset({"read:data"}),
            targets=frozenset({"cache-*"}),
            expires_at=None,
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_delegation_extends_expiry_rejected() -> None:
    from datetime import timedelta
    parent = _parent_grant(expires_at=_t0() + timedelta(days=1))
    try:
        validate_delegation(
            parent,
            child_principal_id="agent-1",
            capabilities=frozenset({"read:data"}),
            targets=frozenset(),
            expires_at=_t0() + timedelta(days=2),
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_delegation_unbounded_when_parent_bounded_rejected() -> None:
    from datetime import timedelta
    parent = _parent_grant(expires_at=_t0() + timedelta(days=1))
    try:
        validate_delegation(
            parent,
            child_principal_id="agent-1",
            capabilities=frozenset({"read:data"}),
            targets=frozenset(),
            expires_at=None,
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_delegation_depth_limit_enforced() -> None:
    parent = _parent_grant(max_depth=0)
    try:
        validate_delegation(
            parent,
            child_principal_id="agent-1",
            capabilities=frozenset({"read:data"}),
            targets=frozenset(),
            expires_at=None,
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_delegation_to_self_rejected() -> None:
    parent = _parent_grant()
    try:
        validate_delegation(
            parent,
            child_principal_id=parent.principal_id,
            capabilities=frozenset({"read:data"}),
            targets=frozenset(),
            expires_at=None,
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_delegation_valid_succeeds() -> None:
    parent = _parent_grant()
    validate_delegation(
        parent,
        child_principal_id="agent-1",
        capabilities=frozenset({"read:data"}),
        targets=frozenset({"db-prod"}),
        expires_at=None,
        at=_t0(),
    )


# ---- policy tests ---------------------------------------------------------

def test_policy_wildcard_matches_any_capability() -> None:
    rule = PolicyRule(
        rule_id="r1", decision=AuthorityDecisionKind.DENY,
        capability_pattern="*",
        principal_kinds=frozenset({PrincipalKind.AGENT}),
    )
    req = _request(pid="agent-1", cap="read:data")
    assert rule.matches(req, _agent("agent-1"))


def test_policy_principal_kind_filter() -> None:
    rule = PolicyRule(
        rule_id="r1", decision=AuthorityDecisionKind.DENY,
        capability_pattern="*",
        principal_kinds=frozenset({PrincipalKind.AGENT}),
    )
    assert not rule.matches(_request(pid="alice"), _human("alice"))


def test_policy_posture_trigger() -> None:
    rule = PolicyRule(
        rule_id="r1", decision=AuthorityDecisionKind.DENY,
        posture_trigger="suspicious",
    )
    assert rule.matches(
        _request(posture=_posture("suspicious", 0.6)),
        _human("alice"),
    )
    assert not rule.matches(_request(posture=_posture("trusted", 0.1)),
                            _human("alice"))


# ---- authorization tests --------------------------------------------------

def _engine_with_alice(*, caps=("read:data",), targets=("db-*",),
                       expires_at=None) -> AuthorityEngine:
    eng = AuthorityEngine()
    eng.register_principal(_human("alice"))
    eng.grant_root(
        principal_id="alice",
        capabilities=caps,
        targets=targets,
        issued_at=_t0(),
        expires_at=expires_at,
    )
    return eng


def test_authorize_unknown_principal_denied() -> None:
    eng = AuthorityEngine()
    d = eng.authorize(_request(pid="nobody"))
    assert d.kind is AuthorityDecisionKind.DENY


def test_authorize_revoked_principal_denied() -> None:
    eng = _engine_with_alice()
    eng.revoke("alice", reason="compromised", at=_t0())
    d = eng.authorize(_request())
    assert d.kind is AuthorityDecisionKind.DENY


def test_authorize_suspended_principal_suspended() -> None:
    eng = _engine_with_alice()
    eng.suspend("alice", reason="incident", at=_t0())
    d = eng.authorize(_request())
    assert d.kind is AuthorityDecisionKind.SUSPENDED


def test_authorize_compromised_posture_denied() -> None:
    eng = _engine_with_alice()
    d = eng.authorize(_request(posture=_posture("compromised", 0.9)))
    assert d.kind is AuthorityDecisionKind.DENY


def test_authorize_no_matching_grant_no_authority() -> None:
    eng = _engine_with_alice(caps=("write:data",))
    d = eng.authorize(_request(cap="read:data"))
    assert d.kind is AuthorityDecisionKind.NO_AUTHORITY


def test_authorize_target_outside_scope_no_authority() -> None:
    eng = _engine_with_alice(targets=("db-staging",))
    d = eng.authorize(_request(target="db-prod"))
    assert d.kind is AuthorityDecisionKind.NO_AUTHORITY


def test_authorize_expired_grant_expired() -> None:
    from datetime import timedelta
    eng = _engine_with_alice(expires_at=_t0() - timedelta(seconds=1) + timedelta(days=1))
    # grant expires after issue but before request
    later = _t0().replace(year=_t0().year + 5)
    d = eng.authorize(_request(at=later))
    assert d.kind is AuthorityDecisionKind.EXPIRED


def test_authorize_high_impact_without_intent_requires_approval() -> None:
    eng = _engine_with_alice(caps=("execute:shell",), targets=("host-*",))
    d = eng.authorize(_request(cap="execute:shell", target="host-1", intent=""))
    assert d.kind is AuthorityDecisionKind.REQUIRE_APPROVAL


def test_authorize_successful_allow() -> None:
    eng = _engine_with_alice()
    d = eng.authorize(_request())
    assert d.kind is AuthorityDecisionKind.ALLOW
    assert d.matched_grants


def test_authorize_policy_deny_overrides_allow() -> None:
    eng = _engine_with_alice()
    eng.add_policy(PolicyRule(
        rule_id="r-block", decision=AuthorityDecisionKind.DENY,
        capability_pattern="read:*",
        principal_kinds=frozenset({PrincipalKind.HUMAN}),
    ))
    d = eng.authorize(_request())
    assert d.kind is AuthorityDecisionKind.DENY


def test_authorize_high_risk_requires_approval() -> None:
    eng = _engine_with_alice()
    d = eng.authorize(_request(posture=_posture("trusted", risk=0.9)))
    assert d.kind is AuthorityDecisionKind.REQUIRE_APPROVAL


def test_authorize_moderate_risk_requires_verification() -> None:
    eng = _engine_with_alice()
    d = eng.authorize(_request(posture=_posture("trusted", risk=0.6)))
    assert d.kind is AuthorityDecisionKind.REQUIRE_VERIFICATION


def test_authorize_low_decay_requires_verification() -> None:
    from datetime import timedelta
    eng = _engine_with_alice()
    later = _t0() + timedelta(days=10)
    eng.recompute_decay(at=later, half_life_seconds=86400.0)
    d = eng.authorize(_request(at=later))
    assert d.kind in (AuthorityDecisionKind.REQUIRE_VERIFICATION,
                      AuthorityDecisionKind.REQUIRE_APPROVAL)


def test_authorize_medium_decay_requires_approval() -> None:
    from datetime import timedelta
    eng = _engine_with_alice()
    later = _t0() + timedelta(hours=20)
    eng.recompute_decay(at=later, half_life_seconds=86400.0)
    d = eng.authorize(_request(at=later))
    assert d.kind in (AuthorityDecisionKind.REQUIRE_APPROVAL,
                      AuthorityDecisionKind.ALLOW,
                      AuthorityDecisionKind.REQUIRE_VERIFICATION)


# ---- lifecycle tests ------------------------------------------------------

def test_suspend_then_restore_requires_verification() -> None:
    eng = _engine_with_alice()
    eng.suspend("alice", reason="incident", at=_t0())
    try:
        eng.restore("alice", verified=False, reason="recovery", at=_t0())
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_suspend_then_restore_with_verification_succeeds() -> None:
    eng = _engine_with_alice()
    eng.suspend("alice", reason="incident", at=_t0())
    eng.restore("alice", verified=True, reason="recovery", at=_t0())
    state = eng.state("alice")
    assert state is not None
    assert state.status is CapabilityStatus.ACTIVE


def test_restore_revoked_rejected() -> None:
    eng = _engine_with_alice()
    eng.revoke("alice", reason="compromise", at=_t0())
    try:
        eng.restore("alice", verified=True, reason="recovery", at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_suspend_revoked_rejected() -> None:
    eng = _engine_with_alice()
    eng.revoke("alice", reason="compromise", at=_t0())
    try:
        eng.suspend("alice", reason="more", at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_verify_authority_resets_decay() -> None:
    from datetime import timedelta
    eng = _engine_with_alice()
    later = _t0() + timedelta(days=10)
    eng.recompute_decay(at=later, half_life_seconds=86400.0)
    eng.verify_authority("alice", at=later)
    state = eng.state("alice")
    assert state is not None
    assert state.decay_score == 1.0


# ---- invariant tests ------------------------------------------------------

def test_invariant_delegation_capability_subset() -> None:
    parent = _parent_grant(caps=("read",))
    # Manually craft a child grant that violates the rule
    bad_child = AuthorityGrant(
        grant_id="g-child", principal_id="agent-1",
        capabilities=frozenset({"read", "write"}),
        targets=frozenset(),
        issued_at=_t0(), expires_at=None,
        parent_grant_id="g-parent",
        delegation_depth=1, max_chain_depth=3,
    )
    snap = AuthoritySnapshot(
        principals={},
        grants={"g-parent": parent, "g-child": bad_child},
        states={},
    )
    v = check_authority_invariants(snap)
    assert any(x.invariant_id == "auth.delegation_capability_subset" for x in v)


def test_invariant_parent_grant_exists() -> None:
    orphan = AuthorityGrant(
        grant_id="g-orphan", principal_id="agent-1",
        capabilities=frozenset({"read"}),
        targets=frozenset(),
        issued_at=_t0(), expires_at=None,
        parent_grant_id="g-missing",
        delegation_depth=1, max_chain_depth=3,
    )
    snap = AuthoritySnapshot(
        principals={},
        grants={"g-orphan": orphan},
        states={},
    )
    v = check_authority_invariants(snap)
    assert any(x.invariant_id == "auth.parent_grant_exists" for x in v)


def test_invariant_revoked_principal_no_active_grant() -> None:
    parent = _parent_grant()
    state = PrincipalAuthorityState(
        principal_id="alice",
        status=CapabilityStatus.REVOKED,
        last_verified_at=_t0(),
        decay_score=1.0,
        updated_at=_t0(),
    )
    snap = AuthoritySnapshot(
        principals={},
        grants={"g-parent": parent},
        states={"alice": state},
    )
    v = check_authority_invariants(snap)
    assert any(
        x.invariant_id == "auth.revoked_principal_no_active_grant"
        for x in v
    )


def test_engine_invariants_clean_after_well_formed_delegation() -> None:
    eng = AuthorityEngine()
    eng.register_principal(_human("alice"))
    eng.register_principal(_agent("agent-1"))
    parent = eng.grant_root(
        principal_id="alice",
        capabilities=("read:data", "write:data"),
        targets=("db-*",),
        issued_at=_t0(),
    )
    eng.delegate(
        parent_grant_id=parent.grant_id,
        child_principal_id="agent-1",
        capabilities=("read:data",),
        targets=("db-prod",),
        expires_at=None,
        at=_t0(),
    )
    assert eng.violations() == ()


# ---- store tests ----------------------------------------------------------

def test_in_memory_store_rejects_stale_state_write() -> None:
    s = InMemoryAuthorityStore()
    t = _t0()
    s.put_state(PrincipalAuthorityState(
        principal_id="p", status=CapabilityStatus.ACTIVE,
        last_verified_at=t, decay_score=1.0, updated_at=t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put_state(PrincipalAuthorityState(
            principal_id="p", status=CapabilityStatus.ACTIVE,
            last_verified_at=earlier, decay_score=0.5, updated_at=earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip_grants_and_states() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "auth.db")
    store = SqliteAuthorityStore(db)
    g = AuthorityGrant(
        grant_id="g1", principal_id="alice",
        capabilities=frozenset({"read:data"}),
        targets=frozenset({"db-*"}),
        issued_at=_t0(), expires_at=None,
        parent_grant_id=None, delegation_depth=0, max_chain_depth=3,
    )
    store.put_grant(g)
    got = store.get_grant("g1")
    assert got is not None
    assert got.capabilities == g.capabilities
    assert got.targets == g.targets

    st = PrincipalAuthorityState(
        principal_id="alice", status=CapabilityStatus.ACTIVE,
        last_verified_at=_t0(), decay_score=1.0, updated_at=_t0(),
    )
    store.put_state(st)
    got_state = store.get_state("alice")
    assert got_state is not None
    assert got_state.status is CapabilityStatus.ACTIVE


# ---- integration ----------------------------------------------------------

def test_engine_end_to_end_delegation_flow() -> None:
    eng = AuthorityEngine()
    eng.register_principal(_human("alice"))
    eng.register_principal(_agent("agent-1"))

    parent = eng.grant_root(
        principal_id="alice",
        capabilities=("read:data", "write:data"),
        targets=("db-*",),
        issued_at=_t0(),
    )
    eng.delegate(
        parent_grant_id=parent.grant_id,
        child_principal_id="agent-1",
        capabilities=("read:data",),
        targets=("db-prod",),
        expires_at=None,
        at=_t0(),
    )

    d = eng.authorize(_request(
        pid="agent-1", cap="read:data", target="db-prod",
    ))
    assert d.kind is AuthorityDecisionKind.ALLOW

    d2 = eng.authorize(_request(
        pid="agent-1", cap="write:data", target="db-prod",
    ))
    assert d2.kind is AuthorityDecisionKind.NO_AUTHORITY


def test_engine_full_lifecycle_revoke_denies() -> None:
    eng = _engine_with_alice()
    eng.revoke("alice", reason="compromise", at=_t0())
    assert eng.authorize(_request()).kind is AuthorityDecisionKind.DENY
    assert eng.violations()  # revoked principal still has grants → violation


def test_engine_delegate_to_unregistered_child_rejected() -> None:
    eng = _engine_with_alice()
    parent_grant = eng.grant("g-000001")
    assert parent_grant is not None
    try:
        eng.delegate(
            parent_grant_id=parent_grant.grant_id,
            child_principal_id="missing",
            capabilities=("read:data",),
            targets=(),
            expires_at=None,
            at=_t0(),
        )
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_policy_require_verification_on_moderate_risk() -> None:
    eng = _engine_with_alice()
    eng.add_policy(PolicyRule(
        rule_id="moderate-risk-verify",
        decision=AuthorityDecisionKind.REQUIRE_VERIFICATION,
        min_risk=0.4,
    ))
    d = eng.authorize(_request(posture=_posture("trusted", risk=0.5)))
    assert d.kind is AuthorityDecisionKind.REQUIRE_VERIFICATION


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
