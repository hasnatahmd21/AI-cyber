"""
HYDRA POST-CORE — PHASE 9: STORAGE + DATABASE SECURITY STATE
================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — databases, storage backends, data assets, roles, backups
  * Database security-context model (TLS, auth, audit, row-level, exposure)
  * Storage security-context model (encryption, ACL, versioning, WORM)
  * Backup security-context model (immutable, offsite, verified, RPO/RTO)
  * Recovery-state model (tested, freshness, integrity verified)
  * Database privilege state (roles, wildcard grants, superuser, grants)
  * Data access-path model (principal → role → db/table capability)
  * Data dependency graph (apps ↔ DBs, replication, cross-region)
  * Continuous trust state per data asset
  * Effective trust bounded by dependencies + backups + recovery
  * 9 break detectors (public exposure, wildcard grants, unencrypted,
    backup missing, recovery untested, replication divergence, integrity
    failure, access-path overreach, dependency discontinuity)
  * Continuity analysis with intrinsic risk
  * Explicit trust-label transitions
  * Machine-checkable data invariants
  * In-memory + SQLite stores
  * Phase-9 engine facade
  * Full test suite + manual runner

This is NEW storage/database security-state technology. It is not a
generic DB monitor, not a DAM, not a backup product.

Run tests:
    python hydra_phase9_storage_database_security_state.py
    pytest hydra_phase9_storage_database_security_state.py -q
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
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


class DatabaseKind(str, Enum):
    RELATIONAL = "relational"
    DOCUMENT = "document"
    KEY_VALUE = "key_value"
    GRAPH = "graph"
    TIME_SERIES = "time_series"
    OBJECT_STORE = "object_store"
    WAREHOUSE = "warehouse"
    SEARCH_INDEX = "search_index"


class StorageKind(str, Enum):
    BLOCK = "block"
    FILE = "file"
    OBJECT = "object"
    ARCHIVE = "archive"
    CDN = "cdn"
    MESSAGE_QUEUE = "message_queue"


class BackupKind(str, Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    SNAPSHOT = "snapshot"
    LOGICAL_DUMP = "logical_dump"
    CONTINUOUS = "continuous"


class AuthMode(str, Enum):
    PASSWORD_ONLY = "password_only"
    PASSWORD_MFA = "password_mfa"
    CERTIFICATE = "certificate"
    IAM_INTEGRATED = "iam_integrated"
    KERBEROS = "kerberos"
    MUTUAL_TLS = "mutual_tls"


class TrustLabel(str, Enum):
    UNKNOWN = "unknown"
    OBSERVED = "observed"
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


_LABEL_SEVERITY: Mapping[TrustLabel, int] = {
    TrustLabel.UNKNOWN: 0,
    TrustLabel.OBSERVED: 1,
    TrustLabel.TRUSTED: 1,
    TrustLabel.DEGRADED: 2,
    TrustLabel.SUSPICIOUS: 3,
    TrustLabel.COMPROMISED: 4,
    TrustLabel.QUARANTINED: 5,
}


def label_severity(label: TrustLabel) -> int:
    return _LABEL_SEVERITY[label]


def worse_of(a: TrustLabel, b: TrustLabel) -> TrustLabel:
    return a if label_severity(a) >= label_severity(b) else b


def is_untrusted(label: TrustLabel) -> bool:
    return label in (
        TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED,
        TrustLabel.QUARANTINED,
    )


class DataBreakKind(str, Enum):
    NONE = "none"
    PUBLIC_EXPOSURE = "public_exposure"
    WILDCARD_GRANT = "wildcard_grant"
    UNENCRYPTED_AT_REST = "unencrypted_at_rest"
    BACKUP_MISSING = "backup_missing"
    RECOVERY_UNTESTED = "recovery_untested"
    REPLICATION_DIVERGENCE = "replication_divergence"
    INTEGRITY_FAILURE = "integrity_failure"
    ACCESS_PATH_OVERREACH = "access_path_overreach"
    DEPENDENCY_DISCONTINUITY = "dependency_discontinuity"


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


def canonical_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# =============================================================================
# SECTION 3 — SECURITY SUB-MODELS
# =============================================================================


WILDCARD_MARKERS: FrozenSet[str] = frozenset({"*", "ALL", "ANY", "%", "PUBLIC"})
SUPERUSER_ROLE_NAMES: FrozenSet[str] = frozenset({
    "superuser", "root", "admin", "cluster-admin", "sysadmin",
    "dba", "owner",
})


@dataclass(frozen=True)
class DatabaseSecurity:
    encryption_at_rest: bool = True
    encryption_in_transit: bool = True
    auth_mode: AuthMode = AuthMode.MUTUAL_TLS
    audit_logging: bool = True
    public_exposure: bool = False
    row_level_security: bool = False
    column_level_encryption: bool = False
    backup_encryption_key_rotation_days: Optional[int] = None

    def dangerous_score(self) -> float:
        s = 0.0
        if not self.encryption_at_rest:
            s += 0.25
        if not self.encryption_in_transit:
            s += 0.20
        if self.auth_mode in (AuthMode.PASSWORD_ONLY, AuthMode.PASSWORD_MFA):
            s += 0.15
        if not self.audit_logging:
            s += 0.15
        if self.public_exposure:
            s += 0.30
        if not self.row_level_security:
            s += 0.05
        if not self.column_level_encryption:
            s += 0.05
        return max(0.0, min(1.0, s))


@dataclass(frozen=True)
class StorageSecurity:
    encryption_at_rest: bool = True
    public_read: bool = False
    public_write: bool = False
    versioning: bool = True
    object_lock_worm: bool = False
    access_logging: bool = True
    lifecycle_policy: bool = True
    cross_region_replication: bool = False

    def dangerous_score(self) -> float:
        s = 0.0
        if not self.encryption_at_rest:
            s += 0.25
        if self.public_read:
            s += 0.30
        if self.public_write:
            s += 0.40
        if not self.versioning:
            s += 0.10
        if not self.access_logging:
            s += 0.10
        if not self.lifecycle_policy:
            s += 0.05
        return max(0.0, min(1.0, s))


@dataclass(frozen=True)
class BackupState:
    kind: BackupKind
    last_backup_at: datetime
    encrypted: bool = True
    offsite: bool = False
    immutable: bool = False
    integrity_verified_at: Optional[datetime] = None
    retention_days: int = 30
    rpo_seconds: int = 3600
    rto_seconds: int = 14400

    def __post_init__(self) -> None:
        if self.last_backup_at.tzinfo is None:
            raise ValueError("last_backup_at must be timezone-aware")
        if self.integrity_verified_at is not None:
            if self.integrity_verified_at.tzinfo is None:
                raise ValueError("integrity_verified_at must be timezone-aware")
        if self.retention_days < 0:
            raise ValueError("retention_days must be non-negative")
        if self.rpo_seconds <= 0 or self.rto_seconds <= 0:
            raise ValueError("rpo/rto must be positive")

    def age_seconds(self, at: datetime) -> float:
        return (at - self.last_backup_at).total_seconds()

    def is_stale(self, at: datetime) -> bool:
        return self.age_seconds(at) > self.rpo_seconds

    def dangerous_score(self, *, at: datetime) -> float:
        s = 0.0
        if self.is_stale(at):
            s += 0.40
        if not self.encrypted:
            s += 0.20
        if not self.offsite:
            s += 0.15
        if not self.immutable:
            s += 0.15
        if self.integrity_verified_at is None:
            s += 0.15
        return max(0.0, min(1.0, s))


@dataclass(frozen=True)
class RecoveryState:
    last_restore_test_at: Optional[datetime]
    last_restore_test_success: bool = False
    verified_recovery_confidence: float = 0.0
    target_rto_met: bool = False

    def __post_init__(self) -> None:
        if self.last_restore_test_at is not None:
            if self.last_restore_test_at.tzinfo is None:
                raise ValueError(
                    "last_restore_test_at must be timezone-aware"
                )
        if not 0.0 <= self.verified_recovery_confidence <= 1.0:
            raise ValueError(
                "verified_recovery_confidence must be within [0,1]"
            )

    def is_fresh(self, at: datetime, *, max_age_days: int = 90) -> bool:
        if self.last_restore_test_at is None:
            return False
        return (at - self.last_restore_test_at).days <= max_age_days

    def dangerous_score(self, at: datetime) -> float:
        s = 0.0
        if self.last_restore_test_at is None:
            s += 0.50
        elif not self.is_fresh(at):
            s += 0.30
        if not self.last_restore_test_success:
            s += 0.20
        s += 0.30 * (1.0 - self.verified_recovery_confidence)
        if not self.target_rto_met:
            s += 0.15
        return max(0.0, min(1.0, s))


@dataclass(frozen=True)
class DataIntegrityState:
    checksum_verified_at: Optional[datetime]
    checksum_verified: bool = False
    row_count_anomaly: bool = False
    schema_drift_detected: bool = False
    replication_lag_seconds: int = 0

    def __post_init__(self) -> None:
        if self.checksum_verified_at is not None:
            if self.checksum_verified_at.tzinfo is None:
                raise ValueError(
                    "checksum_verified_at must be timezone-aware"
                )
        if self.replication_lag_seconds < 0:
            raise ValueError("replication_lag_seconds must be non-negative")

    def dangerous_score(self) -> float:
        s = 0.0
        if not self.checksum_verified:
            s += 0.20
        if self.row_count_anomaly:
            s += 0.30
        if self.schema_drift_detected:
            s += 0.25
        if self.replication_lag_seconds > 300:
            s += 0.25
        elif self.replication_lag_seconds > 60:
            s += 0.10
        return max(0.0, min(1.0, s))


@dataclass(frozen=True)
class RoleGrant:
    role_name: str
    capabilities: FrozenSet[str]           # e.g. {"select", "insert", "ddl"}
    wildcard: bool = False
    superuser: bool = False

    def __post_init__(self) -> None:
        if not self.role_name:
            raise ValueError("role_name is required")
        if not self.capabilities and not self.superuser:
            raise ValueError("role must have capabilities or be superuser")

    @property
    def is_dangerous(self) -> bool:
        if self.superuser:
            return True
        if self.wildcard:
            return True
        if self.capabilities & WILDCARD_MARKERS:
            return True
        if self.role_name.lower() in SUPERUSER_ROLE_NAMES:
            return True
        if {"ddl", "grant", "revoke"} & self.capabilities:
            return True
        return False


@dataclass(frozen=True)
class DataAccessPath:
    principal_id: str
    role_name: str
    resource_id: str
    capabilities: FrozenSet[str]
    granted_at: datetime
    expires_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.principal_id:
            raise ValueError("principal_id is required")
        if not self.role_name:
            raise ValueError("role_name is required")
        if not self.resource_id:
            raise ValueError("resource_id is required")
        if self.granted_at.tzinfo is None:
            raise ValueError("granted_at must be timezone-aware")
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None:
                raise ValueError("expires_at must be timezone-aware")
            if self.expires_at <= self.granted_at:
                raise ValueError("expires_at must be after granted_at")

    def active_at(self, at: datetime) -> bool:
        if self.expires_at is not None and self.expires_at <= at:
            return False
        return self.granted_at <= at

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.principal_id, self.role_name, self.resource_id)


# =============================================================================
# SECTION 4 — DATA ASSETS
# =============================================================================


@dataclass(frozen=True)
class DataAsset:
    asset_id: str
    kind: DatabaseKind
    storage_kind: StorageKind
    name: str
    tenant_id: str
    sensitivity: float               # 0..1
    region: str
    parent_asset_id: Optional[str]   # e.g. replica->primary
    database: DatabaseSecurity
    storage: StorageSecurity
    backup: Optional[BackupState]
    recovery: RecoveryState
    integrity: DataIntegrityState
    roles: FrozenSet[RoleGrant] = frozenset()

    def __post_init__(self) -> None:
        if not self.asset_id:
            raise ValueError("asset_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not self.tenant_id:
            raise ValueError("tenant_id is required")
        if not 0.0 <= self.sensitivity <= 1.0:
            raise ValueError("sensitivity must be within [0,1]")
        if not self.region:
            raise ValueError("region is required")

    def intrinsic_risk(self) -> float:
        return max(
            self.database.dangerous_score(),
            self.storage.dangerous_score(),
        ) * (0.5 + 0.5 * self.sensitivity)


@dataclass(frozen=True)
class DataDependencyEdge:
    dependent_id: str          # application or service
    dependency_id: str         # data asset
    kind: str                  # "read", "write", "replication", "cdc"
    weight: float              # 0<w≤1

    def __post_init__(self) -> None:
        if not self.dependent_id or not self.dependency_id:
            raise ValueError("dependent_id and dependency_id are required")
        if self.dependent_id == self.dependency_id:
            raise ValueError("self-dependencies are not allowed")
        if not 0.0 < self.weight <= 1.0:
            raise ValueError("weight must be in (0,1]")


class DataDependencyGraph:
    def __init__(self) -> None:
        self._out: Dict[str, List[DataDependencyEdge]] = {}
        self._in: Dict[str, List[DataDependencyEdge]] = {}
        self._edges: List[DataDependencyEdge] = []

    def add(self, edge: DataDependencyEdge) -> None:
        for existing in self._out.get(edge.dependent_id, []):
            if existing.dependency_id == edge.dependency_id \
               and existing.kind == edge.kind:
                raise ValueError(
                    f"duplicate dependency {edge.dependent_id}->"
                    f"{edge.dependency_id} ({edge.kind})"
                )
        self._out.setdefault(edge.dependent_id, []).append(edge)
        self._in.setdefault(edge.dependency_id, []).append(edge)
        self._edges.append(edge)

    def dependents_of(self, asset_id: str) -> Tuple[DataDependencyEdge, ...]:
        return tuple(self._in.get(asset_id, []))

    def dependencies_of(self, dependent_id: str) -> Tuple[DataDependencyEdge, ...]:
        return tuple(self._out.get(dependent_id, []))

    def all_edges(self) -> Tuple[DataDependencyEdge, ...]:
        return tuple(self._edges)


# =============================================================================
# SECTION 5 — TRUST STATE
# =============================================================================


NEUTRAL_SCORE = 0.5


@dataclass(frozen=True)
class TrustSignal:
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
class TrustState:
    score: float
    confidence: float
    basis: Tuple[TrustSignal, ...]
    updated_at: datetime

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be within [0,1]")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")
        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")


def neutral_trust(at: datetime) -> TrustState:
    return TrustState(score=NEUTRAL_SCORE, confidence=0.0,
                      basis=(), updated_at=at)


def combine_trust(signals: Iterable[TrustSignal], at: datetime) -> TrustState:
    basis = tuple(sorted(signals, key=lambda s: s.at))
    if not basis:
        return neutral_trust(at)
    num = 0.0
    den = 0.0
    for s in basis:
        num += s.weight * s.polarity
        den += s.weight
    if den <= 0.0:
        return neutral_trust(at)
    raw = num / den
    score = max(0.0, min(1.0, (raw + 1.0) / 2.0))
    confidence = den / (den + 2.0)
    return TrustState(score=score, confidence=confidence,
                      basis=basis, updated_at=at)


def derive_label(trust: TrustState) -> TrustLabel:
    if trust.confidence < 0.4:
        return TrustLabel.UNKNOWN
    s = trust.score
    if s < 0.30:
        return TrustLabel.SUSPICIOUS
    if s < 0.55:
        return TrustLabel.DEGRADED
    if s < 0.85:
        return TrustLabel.OBSERVED
    return TrustLabel.TRUSTED


# =============================================================================
# SECTION 6 — BREAK DETECTORS
# =============================================================================


@dataclass(frozen=True)
class DataBreakFinding:
    kind: DataBreakKind
    asset_id: str
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def detect_public_exposure(
    asset: DataAsset, *, at: datetime,
) -> Optional[DataBreakFinding]:
    if asset.database.public_exposure or asset.storage.public_read \
       or asset.storage.public_write:
        return DataBreakFinding(
            kind=DataBreakKind.PUBLIC_EXPOSURE,
            asset_id=asset.asset_id,
            detail=(
                f"asset {asset.asset_id} exposes public interface "
                f"(db_public={asset.database.public_exposure}, "
                f"read={asset.storage.public_read}, "
                f"write={asset.storage.public_write})"
            ),
            severity=5 if asset.storage.public_write else 4,
            at=at,
        )
    return None


def detect_wildcard_grants(
    asset: DataAsset, *, at: datetime,
) -> Tuple[DataBreakFinding, ...]:
    out: List[DataBreakFinding] = []
    for r in asset.roles:
        if r.superuser:
            out.append(DataBreakFinding(
                kind=DataBreakKind.WILDCARD_GRANT,
                asset_id=asset.asset_id,
                detail=f"role {r.role_name} is superuser on {asset.asset_id}",
                severity=5,
                at=at,
            ))
        elif r.wildcard or (r.capabilities & WILDCARD_MARKERS):
            out.append(DataBreakFinding(
                kind=DataBreakKind.WILDCARD_GRANT,
                asset_id=asset.asset_id,
                detail=(
                    f"role {r.role_name} has wildcard capabilities on "
                    f"{asset.asset_id}: {sorted(r.capabilities)}"
                ),
                severity=4,
                at=at,
            ))
    return tuple(out)


def detect_unencrypted_at_rest(
    asset: DataAsset, *, at: datetime,
) -> Optional[DataBreakFinding]:
    if not asset.database.encryption_at_rest or not asset.storage.encryption_at_rest:
        return DataBreakFinding(
            kind=DataBreakKind.UNENCRYPTED_AT_REST,
            asset_id=asset.asset_id,
            detail=(
                f"asset {asset.asset_id} has unencrypted storage "
                f"(db={asset.database.encryption_at_rest}, "
                f"storage={asset.storage.encryption_at_rest})"
            ),
            severity=4,
            at=at,
        )
    return None


def detect_backup_missing(
    asset: DataAsset, *, at: datetime,
) -> Optional[DataBreakFinding]:
    if asset.backup is None:
        return DataBreakFinding(
            kind=DataBreakKind.BACKUP_MISSING,
            asset_id=asset.asset_id,
            detail=f"asset {asset.asset_id} has no backup configuration",
            severity=4,
            at=at,
        )
    if asset.backup.is_stale(at):
        return DataBreakFinding(
            kind=DataBreakKind.BACKUP_MISSING,
            asset_id=asset.asset_id,
            detail=(
                f"asset {asset.asset_id} backup stale: age "
                f"{asset.backup.age_seconds(at):.0f}s > RPO "
                f"{asset.backup.rpo_seconds}s"
            ),
            severity=4,
            at=at,
        )
    return None


def detect_recovery_untested(
    asset: DataAsset, *, at: datetime,
) -> Optional[DataBreakFinding]:
    if not asset.recovery.is_fresh(at):
        return DataBreakFinding(
            kind=DataBreakKind.RECOVERY_UNTESTED,
            asset_id=asset.asset_id,
            detail=(
                f"asset {asset.asset_id} has no fresh restore test "
                f"(last={asset.recovery.last_restore_test_at})"
            ),
            severity=4,
            at=at,
        )
    if not asset.recovery.last_restore_test_success:
        return DataBreakFinding(
            kind=DataBreakKind.RECOVERY_UNTESTED,
            asset_id=asset.asset_id,
            detail=(
                f"asset {asset.asset_id} last restore test failed"
            ),
            severity=5,
            at=at,
        )
    return None


def detect_replication_divergence(
    asset: DataAsset, *, at: datetime,
) -> Optional[DataBreakFinding]:
    if asset.integrity.replication_lag_seconds > 300:
        return DataBreakFinding(
            kind=DataBreakKind.REPLICATION_DIVERGENCE,
            asset_id=asset.asset_id,
            detail=(
                f"asset {asset.asset_id} replication lag "
                f"{asset.integrity.replication_lag_seconds}s"
            ),
            severity=4,
            at=at,
        )
    if asset.integrity.row_count_anomaly:
        return DataBreakFinding(
            kind=DataBreakKind.REPLICATION_DIVERGENCE,
            asset_id=asset.asset_id,
            detail=f"asset {asset.asset_id} row count anomaly",
            severity=4,
            at=at,
        )
    return None


def detect_integrity_failure(
    asset: DataAsset, *, at: datetime,
) -> Optional[DataBreakFinding]:
    if asset.integrity.schema_drift_detected:
        return DataBreakFinding(
            kind=DataBreakKind.INTEGRITY_FAILURE,
            asset_id=asset.asset_id,
            detail=f"asset {asset.asset_id} schema drift detected",
            severity=4,
            at=at,
        )
    if not asset.integrity.checksum_verified:
        return DataBreakFinding(
            kind=DataBreakKind.INTEGRITY_FAILURE,
            asset_id=asset.asset_id,
            detail=f"asset {asset.asset_id} checksum never verified",
            severity=3,
            at=at,
        )
    return None


def detect_access_path_overreach(
    asset: DataAsset,
    *,
    access_paths: Iterable[DataAccessPath],
    at: datetime,
) -> Tuple[DataBreakFinding, ...]:
    """Any active access path with dangerous capabilities to this asset."""
    out: List[DataBreakFinding] = []
    for p in access_paths:
        if p.resource_id != asset.asset_id:
            continue
        if not p.active_at(at):
            continue
        caps = p.capabilities
        dangerous = (
            (caps & WILDCARD_MARKERS)
            or ("ddl" in caps)
            or ("grant" in caps)
            or ("revoke" in caps)
            or ("delete" in caps and "where" not in caps)
        )
        if dangerous:
            out.append(DataBreakFinding(
                kind=DataBreakKind.ACCESS_PATH_OVERREACH,
                asset_id=asset.asset_id,
                detail=(
                    f"principal {p.principal_id} → role {p.role_name} "
                    f"has dangerous capabilities on {asset.asset_id}: "
                    f"{sorted(caps)}"
                ),
                severity=4,
                at=at,
            ))
    return tuple(out)


def detect_dependency_discontinuity(
    graph: DataDependencyGraph,
    asset_id: str,
    *,
    known_entities: FrozenSet[str],
    at: datetime,
) -> Tuple[DataBreakFinding, ...]:
    out: List[DataBreakFinding] = []
    for e in graph.dependents_of(asset_id):
        if e.dependent_id not in known_entities:
            out.append(DataBreakFinding(
                kind=DataBreakKind.DEPENDENCY_DISCONTINUITY,
                asset_id=asset_id,
                detail=(
                    f"asset {asset_id} has dependent {e.dependent_id} "
                    f"not present in registry"
                ),
                severity=3,
                at=at,
            ))
    return tuple(out)


# =============================================================================
# SECTION 7 — CONTINUITY ANALYSIS
# =============================================================================


@dataclass(frozen=True)
class DataContinuityResult:
    asset_id: str
    label: TrustLabel
    trust: TrustState
    continuity: float
    findings: Tuple[DataBreakFinding, ...]
    dependency_ceiling: Optional[float]
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 0.0 <= self.continuity <= 1.0:
            raise ValueError("continuity must be within [0,1]")


TRUST_SLACK: float = 0.1


def effective_data_trust(
    *,
    observed: float,
    dependency_scores: Iterable[float],
    intrinsic_risk: float,
    findings: Iterable[DataBreakFinding],
    slack: float = TRUST_SLACK,
) -> float:
    if not 0.0 <= observed <= 1.0:
        raise ValueError("observed must be within [0,1]")
    base = observed
    deps = [d for d in dependency_scores]
    if deps:
        ceiling = min(1.0, min(deps) + slack)
        base = min(base, ceiling)
    base *= (1.0 - 0.5 * max(0.0, min(1.0, intrinsic_risk)))
    penalty = 0.0
    for f in findings:
        penalty += 0.05 * f.severity
    return max(0.0, min(1.0, base - penalty))


def analyse_data_continuity(
    asset: DataAsset,
    *,
    signals: Iterable[TrustSignal],
    dependency_scores: Mapping[str, float],
    findings: Tuple[DataBreakFinding, ...],
    at: datetime,
) -> DataContinuityResult:
    observed_state = combine_trust(signals, at)
    intrinsic = asset.intrinsic_risk()

    dep_ceiling: Optional[float] = None
    if asset.parent_asset_id is not None:
        parent_score = dependency_scores.get(asset.parent_asset_id)
        if parent_score is not None:
            dep_ceiling = parent_score

    continuity = effective_data_trust(
        observed=observed_state.score,
        dependency_scores=([dep_ceiling] if dep_ceiling is not None else []),
        intrinsic_risk=intrinsic,
        findings=findings,
    )

    provisional = TrustState(
        score=continuity, confidence=observed_state.confidence,
        basis=observed_state.basis, updated_at=at,
    )
    label = derive_label(provisional)

    for f in findings:
        if f.severity >= 5:
            label = worse_of(label, TrustLabel.COMPROMISED)
        elif f.severity >= 4:
            label = worse_of(label, TrustLabel.SUSPICIOUS)
        elif f.severity >= 3:
            label = worse_of(label, TrustLabel.DEGRADED)

    rationale = (
        f"asset {asset.asset_id} continuity {continuity:.2f}, "
        f"intrinsic risk {intrinsic:.2f}, {len(findings)} finding(s)"
    )

    return DataContinuityResult(
        asset_id=asset.asset_id,
        label=label,
        trust=TrustState(
            score=continuity, confidence=observed_state.confidence,
            basis=observed_state.basis, updated_at=at,
        ),
        continuity=continuity,
        findings=findings,
        dependency_ceiling=dep_ceiling,
        rationale=rationale,
        at=at,
    )


# =============================================================================
# SECTION 8 — TRANSITIONS
# =============================================================================


class TransitionOutcome(str, Enum):
    ALLOWED = "allowed"
    REJECTED_INVALID = "rejected_invalid"
    REQUIRES_VERIFICATION = "requires_verification"


_ALLOWED_LABEL_EDGES: Mapping[TrustLabel, FrozenSet[TrustLabel]] = {
    TrustLabel.UNKNOWN: frozenset({
        TrustLabel.OBSERVED, TrustLabel.DEGRADED, TrustLabel.SUSPICIOUS,
    }),
    TrustLabel.OBSERVED: frozenset({
        TrustLabel.TRUSTED, TrustLabel.DEGRADED,
        TrustLabel.SUSPICIOUS, TrustLabel.COMPROMISED,
    }),
    TrustLabel.TRUSTED: frozenset({
        TrustLabel.DEGRADED, TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
    }),
    TrustLabel.DEGRADED: frozenset({
        TrustLabel.OBSERVED, TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
    }),
    TrustLabel.SUSPICIOUS: frozenset({
        TrustLabel.OBSERVED, TrustLabel.DEGRADED,
        TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
    }),
    TrustLabel.COMPROMISED: frozenset({TrustLabel.QUARANTINED}),
    TrustLabel.QUARANTINED: frozenset({TrustLabel.OBSERVED}),
}


@dataclass(frozen=True)
class TransitionRequest:
    entity_id: str
    from_label: TrustLabel
    to_label: TrustLabel
    reason: str
    verified: bool


@dataclass(frozen=True)
class TransitionDecision:
    outcome: TransitionOutcome
    rationale: str


def evaluate_transition(req: TransitionRequest) -> TransitionDecision:
    if not req.reason:
        return TransitionDecision(
            TransitionOutcome.REJECTED_INVALID, "reason is required"
        )
    if req.from_label is req.to_label:
        return TransitionDecision(TransitionOutcome.ALLOWED, "no-op")
    permitted = _ALLOWED_LABEL_EDGES.get(req.from_label, frozenset())
    if req.to_label not in permitted:
        return TransitionDecision(
            TransitionOutcome.REJECTED_INVALID,
            f"{req.from_label.value} -> {req.to_label.value} not permitted",
        )
    going_better = label_severity(req.to_label) < label_severity(req.from_label)
    if going_better and not req.verified:
        return TransitionDecision(
            TransitionOutcome.REQUIRES_VERIFICATION,
            "recovery transitions require verification",
        )
    return TransitionDecision(TransitionOutcome.ALLOWED, "permitted")


# =============================================================================
# SECTION 9 — INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AssetSnapshot:
    asset: DataAsset
    label: TrustLabel
    continuity: float
    findings: Tuple[DataBreakFinding, ...]


@dataclass(frozen=True)
class StorageSnapshot:
    assets: Mapping[str, AssetSnapshot]
    graph: DataDependencyGraph
    access_paths: Tuple[DataAccessPath, ...]


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class DataInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[StorageSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_no_trusted_with_public_exposure(
    snap: StorageSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, s in snap.assets.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        a = s.asset
        if a.database.public_exposure or a.storage.public_read \
           or a.storage.public_write:
            out.append(InvariantViolation(
                invariant_id="data.no_trusted_with_public_exposure",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail=f"TRUSTED asset {aid} is publicly exposed",
            ))
    return tuple(out)


def _inv_no_trusted_with_wildcard_grant(
    snap: StorageSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, s in snap.assets.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        for r in s.asset.roles:
            if r.is_dangerous:
                out.append(InvariantViolation(
                    invariant_id="data.no_trusted_with_wildcard_grant",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=aid,
                    detail=(
                        f"TRUSTED asset {aid} has dangerous role "
                        f"{r.role_name}"
                    ),
                ))
    return tuple(out)


def _inv_no_trusted_without_recovery_verification(
    snap: StorageSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, s in snap.assets.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        r = s.asset.recovery
        if r.last_restore_test_at is None \
           or not r.last_restore_test_success \
           or r.verified_recovery_confidence < 0.5:
            out.append(InvariantViolation(
                invariant_id="data.no_trusted_without_recovery",
                severity=InvariantSeverity.HIGH,
                subject_id=aid,
                detail=(
                    f"TRUSTED asset {aid} has unverified recovery "
                    f"(confidence={r.verified_recovery_confidence:.2f})"
                ),
            ))
    return tuple(out)


def _inv_trusted_requires_backup(
    snap: StorageSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, s in snap.assets.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        if s.asset.backup is None:
            out.append(InvariantViolation(
                invariant_id="data.trusted_requires_backup",
                severity=InvariantSeverity.HIGH,
                subject_id=aid,
                detail=f"TRUSTED asset {aid} has no backup configuration",
            ))
    return tuple(out)


def _inv_no_trusted_replica_of_untrusted_primary(
    snap: StorageSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, s in snap.assets.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        parent_id = s.asset.parent_asset_id
        if parent_id is None:
            continue
        ps = snap.assets.get(parent_id)
        if ps is None:
            continue
        if is_untrusted(ps.label):
            out.append(InvariantViolation(
                invariant_id="data.trusted_replica_of_untrusted_primary",
                severity=InvariantSeverity.CRITICAL,
                subject_id=aid,
                detail=(
                    f"{aid} TRUSTED while parent {parent_id} is "
                    f"{ps.label.value}"
                ),
            ))
    return tuple(out)


def _inv_high_sensitivity_must_be_encrypted(
    snap: StorageSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for aid, s in snap.assets.items():
        a = s.asset
        if a.sensitivity >= 0.7:
            if not a.database.encryption_at_rest \
               or not a.storage.encryption_at_rest:
                out.append(InvariantViolation(
                    invariant_id="data.high_sensitivity_unencrypted",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=aid,
                    detail=(
                        f"high-sensitivity asset {aid} "
                        f"(sensitivity={a.sensitivity:.2f}) is unencrypted"
                    ),
                ))
    return tuple(out)


def _inv_access_paths_active_only_on_trusted(
    snap: StorageSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for p in snap.access_paths:
        s = snap.assets.get(p.resource_id)
        if s is None:
            continue
        if is_untrusted(s.label):
            out.append(InvariantViolation(
                invariant_id="data.access_path_on_untrusted_asset",
                severity=InvariantSeverity.HIGH,
                subject_id=p.resource_id,
                detail=(
                    f"active access path from {p.principal_id} on "
                    f"untrusted asset {p.resource_id} "
                    f"({s.label.value})"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[DataInvariant, ...] = (
    DataInvariant(
        invariant_id="data.no_trusted_with_public_exposure",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_trusted_with_public_exposure,
        description="TRUSTED data must not be publicly exposed.",
    ),
    DataInvariant(
        invariant_id="data.no_trusted_with_wildcard_grant",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_trusted_with_wildcard_grant,
        description="TRUSTED data must not have dangerous roles.",
    ),
    DataInvariant(
        invariant_id="data.no_trusted_without_recovery",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_no_trusted_without_recovery_verification,
        description="TRUSTED data must have verified recovery.",
    ),
    DataInvariant(
        invariant_id="data.trusted_requires_backup",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_trusted_requires_backup,
        description="TRUSTED data must have a backup.",
    ),
    DataInvariant(
        invariant_id="data.trusted_replica_of_untrusted_primary",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_trusted_replica_of_untrusted_primary,
        description="Replica cannot be TRUSTED if primary is untrusted.",
    ),
    DataInvariant(
        invariant_id="data.high_sensitivity_unencrypted",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_high_sensitivity_must_be_encrypted,
        description="High-sensitivity data must be encrypted at rest.",
    ),
    DataInvariant(
        invariant_id="data.access_path_on_untrusted_asset",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_access_paths_active_only_on_trusted,
        description="Active access paths must not target untrusted data.",
    ),
)


def check_invariants(
    snap: StorageSnapshot,
    invariants: Iterable[DataInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 10 — STORES
# =============================================================================


@dataclass(frozen=True)
class AssetStateRecord:
    asset_id: str
    label: TrustLabel
    continuity: float
    findings_count: int
    updated_at: datetime


class DataStateStore(Protocol):
    def get(self, asset_id: str) -> Optional[AssetStateRecord]: ...
    def put(self, record: AssetStateRecord) -> None: ...
    def all(self) -> Tuple[AssetStateRecord, ...]: ...
    def put_access_path(self, path: DataAccessPath) -> None: ...
    def delete_access_path(
        self, principal_id: str, role_name: str, resource_id: str,
    ) -> None: ...
    def all_access_paths(self) -> Tuple[DataAccessPath, ...]: ...


class InMemoryDataStateStore:
    def __init__(self) -> None:
        self._assets: Dict[str, AssetStateRecord] = {}
        self._paths: Dict[Tuple[str, str, str], DataAccessPath] = {}

    def get(self, asset_id: str) -> Optional[AssetStateRecord]:
        return self._assets.get(asset_id)

    def put(self, record: AssetStateRecord) -> None:
        existing = self._assets.get(record.asset_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._assets[record.asset_id] = record

    def all(self) -> Tuple[AssetStateRecord, ...]:
        return tuple(self._assets.values())

    def put_access_path(self, path: DataAccessPath) -> None:
        existing = self._paths.get(path.key)
        if existing is not None and existing.granted_at > path.granted_at:
            raise ValueError(
                "refusing to overwrite newer access path with older grant"
            )
        self._paths[path.key] = path

    def delete_access_path(
        self, principal_id: str, role_name: str, resource_id: str,
    ) -> None:
        self._paths.pop((principal_id, role_name, resource_id), None)

    def all_access_paths(self) -> Tuple[DataAccessPath, ...]:
        return tuple(self._paths.values())


class SqliteDataStateStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS data_asset_state (
                asset_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                continuity REAL NOT NULL,
                findings_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS data_access_paths (
                principal_id TEXT NOT NULL,
                role_name TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                capabilities_json TEXT NOT NULL,
                granted_at TEXT NOT NULL,
                expires_at TEXT,
                PRIMARY KEY (principal_id, role_name, resource_id)
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS data_break_findings (
                finding_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, asset_id: str) -> Optional[AssetStateRecord]:
        row = self._conn.execute(
            "SELECT label, continuity, findings_count, updated_at "
            "FROM data_asset_state WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()
        if row is None:
            return None
        return AssetStateRecord(
            asset_id=asset_id,
            label=TrustLabel(row[0]),
            continuity=float(row[1]),
            findings_count=int(row[2]),
            updated_at=datetime.fromisoformat(row[3]),
        )

    def put(self, record: AssetStateRecord) -> None:
        existing = self.get(record.asset_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO data_asset_state
              (asset_id, label, continuity, findings_count, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(asset_id) DO UPDATE SET
              label=excluded.label,
              continuity=excluded.continuity,
              findings_count=excluded.findings_count,
              updated_at=excluded.updated_at
            """,
            (record.asset_id, record.label.value, record.continuity,
             record.findings_count, record.updated_at.isoformat()),
        )
        self._conn.commit()

    def all(self) -> Tuple[AssetStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT asset_id FROM data_asset_state"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_access_path(self, path: DataAccessPath) -> None:
        existing = self._get_access_path(
            path.principal_id, path.role_name, path.resource_id,
        )
        if existing is not None and existing.granted_at > path.granted_at:
            raise ValueError(
                "refusing to overwrite newer access path with older grant"
            )
        self._conn.execute(
            """
            INSERT INTO data_access_paths
              (principal_id, role_name, resource_id, capabilities_json,
               granted_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(principal_id, role_name, resource_id) DO UPDATE SET
              capabilities_json=excluded.capabilities_json,
              granted_at=excluded.granted_at,
              expires_at=excluded.expires_at
            """,
            (
                path.principal_id, path.role_name, path.resource_id,
                json.dumps(sorted(path.capabilities)),
                path.granted_at.isoformat(),
                path.expires_at.isoformat() if path.expires_at else None,
            ),
        )
        self._conn.commit()

    def _get_access_path(
        self, principal_id: str, role_name: str, resource_id: str,
    ) -> Optional[DataAccessPath]:
        row = self._conn.execute(
            "SELECT capabilities_json, granted_at, expires_at "
            "FROM data_access_paths WHERE principal_id = ? AND "
            "role_name = ? AND resource_id = ?",
            (principal_id, role_name, resource_id),
        ).fetchone()
        if row is None:
            return None
        return DataAccessPath(
            principal_id=principal_id, role_name=role_name,
            resource_id=resource_id,
            capabilities=frozenset(json.loads(row[0])),
            granted_at=datetime.fromisoformat(row[1]),
            expires_at=datetime.fromisoformat(row[2]) if row[2] else None,
        )

    def delete_access_path(
        self, principal_id: str, role_name: str, resource_id: str,
    ) -> None:
        self._conn.execute(
            "DELETE FROM data_access_paths WHERE principal_id = ? "
            "AND role_name = ? AND resource_id = ?",
            (principal_id, role_name, resource_id),
        )
        self._conn.commit()

    def all_access_paths(self) -> Tuple[DataAccessPath, ...]:
        rows = self._conn.execute(
            "SELECT principal_id, role_name, resource_id FROM data_access_paths"
        ).fetchall()
        out: List[DataAccessPath] = []
        for r in rows:
            p = self._get_access_path(r[0], r[1], r[2])
            if p is not None:
                out.append(p)
        return tuple(out)


# =============================================================================
# SECTION 11 — ENGINE
# =============================================================================


class StorageDatabaseStateEngine:
    """Continuous storage + database security-state engine."""

    def __init__(self, *, store: Optional[DataStateStore] = None) -> None:
        self._store: DataStateStore = store or InMemoryDataStateStore()
        self._assets: Dict[str, DataAsset] = {}
        self._signals: Dict[str, List[TrustSignal]] = {}
        self._graph = DataDependencyGraph()
        self._labels: Dict[str, TrustLabel] = {}
        self._continuity: Dict[str, DataContinuityResult] = {}
        self._findings: Dict[str, List[DataBreakFinding]] = {}
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._known_entities: set = set()

    # ---- registration ----------------------------------------------------

    def register_entity(self, entity_id: str) -> None:
        if not entity_id:
            raise ValueError("entity_id is required")
        self._known_entities.add(entity_id)

    def register_asset(self, asset: DataAsset) -> None:
        if asset.asset_id in self._assets:
            raise ValueError(f"asset {asset.asset_id} already registered")
        self._assets[asset.asset_id] = asset
        self._known_entities.add(asset.asset_id)
        self._findings[asset.asset_id] = []

    def add_dependency(self, edge: DataDependencyEdge) -> None:
        if edge.dependent_id not in self._known_entities:
            raise KeyError(
                f"dependent {edge.dependent_id} not registered"
            )
        if edge.dependency_id not in self._assets:
            raise KeyError(
                f"dependency {edge.dependency_id} not registered as data asset"
            )
        self._graph.add(edge)

    def grant_access(self, path: DataAccessPath) -> None:
        if path.resource_id not in self._assets:
            raise KeyError(
                f"access path target {path.resource_id} not registered"
            )
        self._store.put_access_path(path)

    def revoke_access(
        self, principal_id: str, role_name: str, resource_id: str,
    ) -> None:
        self._store.delete_access_path(principal_id, role_name, resource_id)

    # ---- signals ---------------------------------------------------------

    def observe_signal(self, asset_id: str, signal: TrustSignal) -> None:
        if asset_id not in self._assets:
            raise KeyError(f"unknown asset {asset_id}")
        if signal.at.tzinfo is None:
            raise ValueError("signal.at must be timezone-aware")
        self._signals.setdefault(asset_id, []).append(signal)

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[AssetStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        # 1. Structural finding detection per asset.
        access_paths = self._store.all_access_paths()
        for aid, asset in self._assets.items():
            self._findings[aid] = []  # reset derived findings

            for fn in (
                detect_public_exposure,
                detect_unencrypted_at_rest,
                detect_backup_missing,
                detect_recovery_untested,
                detect_replication_divergence,
                detect_integrity_failure,
            ):
                f = fn(asset, at=at)
                if f is not None:
                    self._findings[aid].append(f)

            self._findings[aid].extend(
                detect_wildcard_grants(asset, at=at)
            )
            self._findings[aid].extend(
                detect_access_path_overreach(
                    asset, access_paths=access_paths, at=at,
                )
            )
            self._findings[aid].extend(
                detect_dependency_discontinuity(
                    self._graph, aid,
                    known_entities=frozenset(self._known_entities),
                    at=at,
                )
            )

        # 2. Compute continuity per asset, with two-pass for dependency
        #    ceilings.
        observed_scores: Dict[str, float] = {}
        for aid in self._assets:
            st = combine_trust(self._signals.get(aid, []), at)
            observed_scores[aid] = st.score

        records: List[AssetStateRecord] = []
        for aid, asset in self._assets.items():
            result = analyse_data_continuity(
                asset,
                signals=self._signals.get(aid, []),
                dependency_scores=observed_scores,
                findings=tuple(self._findings[aid]),
                at=at,
            )
            self._continuity[aid] = result

            previous = self._labels.get(aid, TrustLabel.UNKNOWN)
            if previous is not result.label:
                verified = (
                    result.continuity >= 0.6
                    and not is_untrusted(result.label)
                )
                decision = evaluate_transition(TransitionRequest(
                    entity_id=aid,
                    from_label=previous,
                    to_label=result.label,
                    reason="recompute",
                    verified=verified,
                ))
                if decision.outcome in (
                    TransitionOutcome.REJECTED_INVALID,
                    TransitionOutcome.REQUIRES_VERIFICATION,
                ):
                    result = DataContinuityResult(
                        asset_id=result.asset_id,
                        label=previous,
                        trust=result.trust,
                        continuity=result.continuity,
                        findings=result.findings,
                        dependency_ceiling=result.dependency_ceiling,
                        rationale=result.rationale + " | transition held",
                        at=result.at,
                    )

            self._labels[aid] = result.label

            rec = AssetStateRecord(
                asset_id=aid,
                label=result.label,
                continuity=result.continuity,
                findings_count=len(result.findings),
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def label(self, asset_id: str) -> Optional[TrustLabel]:
        return self._labels.get(asset_id)

    def continuity(self, asset_id: str) -> Optional[DataContinuityResult]:
        return self._continuity.get(asset_id)

    def state(self, asset_id: str) -> Optional[AssetStateRecord]:
        return self._store.get(asset_id)

    def findings(self, asset_id: str) -> Tuple[DataBreakFinding, ...]:
        return tuple(self._findings.get(asset_id, ()))

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def snapshot(self) -> StorageSnapshot:
        assets: Dict[str, AssetSnapshot] = {}
        for aid, a in self._assets.items():
            rec = self._store.get(aid)
            if rec is None:
                continue
            assets[aid] = AssetSnapshot(
                asset=a,
                label=rec.label,
                continuity=rec.continuity,
                findings=tuple(self._findings.get(aid, ())),
            )
        return StorageSnapshot(
            assets=assets,
            graph=self._graph,
            access_paths=self._store.all_access_paths(),
        )


# =============================================================================
# SECTION 12 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ev(at: datetime, conf: float = 0.9) -> Evidence:
    return Evidence(evidence_id="e", source="test", confidence=conf,
                    observed_at=at, payload={})


def _pos(sid: str = "s", at: Optional[datetime] = None) -> TrustSignal:
    t = at or _t0()
    return TrustSignal(sid, 1.0, 1.0, t, _ev(t))


def _neg(sid: str = "s", at: Optional[datetime] = None) -> TrustSignal:
    t = at or _t0()
    return TrustSignal(sid, 1.0, -1.0, t, _ev(t))


def _secure_db(*, public: bool = False) -> DatabaseSecurity:
    return DatabaseSecurity(
        encryption_at_rest=True, encryption_in_transit=True,
        auth_mode=AuthMode.MUTUAL_TLS, audit_logging=True,
        public_exposure=public, row_level_security=True,
        column_level_encryption=True,
    )


def _secure_storage() -> StorageSecurity:
    return StorageSecurity(
        encryption_at_rest=True, public_read=False, public_write=False,
        versioning=True, object_lock_worm=True, access_logging=True,
        lifecycle_policy=True,
    )


def _secure_backup(at: datetime) -> BackupState:
    return BackupState(
        kind=BackupKind.CONTINUOUS, last_backup_at=at,
        encrypted=True, offsite=True, immutable=True,
        integrity_verified_at=at, retention_days=90,
        rpo_seconds=3600, rto_seconds=3600,
    )


def _secure_recovery(at: datetime) -> RecoveryState:
    return RecoveryState(
        last_restore_test_at=at, last_restore_test_success=True,
        verified_recovery_confidence=0.95, target_rto_met=True,
    )


def _secure_integrity(at: datetime) -> DataIntegrityState:
    return DataIntegrityState(
        checksum_verified_at=at, checksum_verified=True,
        row_count_anomaly=False, schema_drift_detected=False,
        replication_lag_seconds=0,
    )


_ASSET_BACKUP_UNSET = object()


def _asset(
    aid: str = "db1", *, sensitivity: float = 0.5,
    db: Optional[DatabaseSecurity] = None,
    storage: Optional[StorageSecurity] = None,
    backup: Any = _ASSET_BACKUP_UNSET,
    recovery: Optional[RecoveryState] = None,
    integrity: Optional[DataIntegrityState] = None,
    roles: Iterable[RoleGrant] = (),
    parent: Optional[str] = None,
    region: str = "us-east-1",
) -> DataAsset:
    t = _t0()
    return DataAsset(
        asset_id=aid, kind=DatabaseKind.RELATIONAL,
        storage_kind=StorageKind.BLOCK, name=aid, tenant_id="t1",
        sensitivity=sensitivity, region=region,
        parent_asset_id=parent,
        database=db or _secure_db(),
        storage=storage or _secure_storage(),
        backup=(
            _secure_backup(t) if backup is _ASSET_BACKUP_UNSET else backup
        ),
        recovery=recovery or _secure_recovery(t),
        integrity=integrity or _secure_integrity(t),
        roles=frozenset(roles),
    )


# ---- domain tests ---------------------------------------------------------

def test_asset_id_required() -> None:
    try:
        DataAsset(
            asset_id="", kind=DatabaseKind.RELATIONAL,
            storage_kind=StorageKind.BLOCK, name="x", tenant_id="t",
            sensitivity=0.5, region="r", parent_asset_id=None,
            database=_secure_db(), storage=_secure_storage(),
            backup=None, recovery=_secure_recovery(_t0()),
            integrity=_secure_integrity(_t0()),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_backup_stale_detection() -> None:
    old = _t0() - timedelta(hours=10)
    b = BackupState(kind=BackupKind.FULL, last_backup_at=old)
    assert b.is_stale(_t0())


def test_backup_score_penalizes_stale() -> None:
    old = _t0() - timedelta(hours=10)
    b = BackupState(kind=BackupKind.FULL, last_backup_at=old)
    assert b.dangerous_score(at=_t0()) >= 0.4


def test_recovery_score_no_test() -> None:
    r = RecoveryState(last_restore_test_at=None)
    assert r.dangerous_score(_t0()) >= 0.5


def test_role_superuser_dangerous() -> None:
    r = RoleGrant(role_name="admin", capabilities=frozenset({"select"}),
                  superuser=True)
    assert r.is_dangerous


def test_role_wildcard_dangerous() -> None:
    r = RoleGrant(role_name="reader", capabilities=frozenset({"*"}),
                  wildcard=True)
    assert r.is_dangerous


def test_role_ddl_dangerous() -> None:
    r = RoleGrant(role_name="developer",
                  capabilities=frozenset({"select", "ddl"}))
    assert r.is_dangerous


def test_role_read_only_safe() -> None:
    r = RoleGrant(role_name="reader",
                  capabilities=frozenset({"select"}))
    assert not r.is_dangerous


def test_access_path_active() -> None:
    p = DataAccessPath(
        principal_id="u", role_name="r", resource_id="d",
        capabilities=frozenset({"select"}), granted_at=_t0(),
    )
    assert p.active_at(_t0())


def test_access_path_expired() -> None:
    p = DataAccessPath(
        principal_id="u", role_name="r", resource_id="d",
        capabilities=frozenset({"select"}), granted_at=_t0(),
        expires_at=_t0() + timedelta(seconds=1),
    )
    assert not p.active_at(_t0() + timedelta(hours=1))


# ---- trust tests ----------------------------------------------------------

def test_combine_trust_empty_neutral() -> None:
    st = combine_trust([], _t0())
    assert st.score == NEUTRAL_SCORE and st.confidence == 0.0


def test_combine_trust_positive_high() -> None:
    assert combine_trust([_pos()], _t0()).score == 1.0


def test_combine_trust_negative_low() -> None:
    assert combine_trust([_neg()], _t0()).score == 0.0


def test_derive_label_unknown_low_conf() -> None:
    st = TrustState(0.9, 0.1, (), _t0())
    assert derive_label(st) is TrustLabel.UNKNOWN


def test_derive_label_trusted() -> None:
    st = TrustState(0.95, 0.9, (), _t0())
    assert derive_label(st) is TrustLabel.TRUSTED


# ---- break detectors ------------------------------------------------------

def test_detect_public_exposure_db() -> None:
    a = _asset(db=_secure_db(public=True))
    f = detect_public_exposure(a, at=_t0())
    assert f is not None and f.kind is DataBreakKind.PUBLIC_EXPOSURE


def test_detect_public_write_worst_severity() -> None:
    storage = StorageSecurity(
        encryption_at_rest=True, public_read=False, public_write=True,
    )
    a = _asset(storage=storage)
    f = detect_public_exposure(a, at=_t0())
    assert f is not None and f.severity == 5


def test_detect_wildcard_role() -> None:
    role = RoleGrant(role_name="dba",
                     capabilities=frozenset({"select"}), superuser=True)
    a = _asset(roles=(role,))
    findings = detect_wildcard_grants(a, at=_t0())
    assert any(f.kind is DataBreakKind.WILDCARD_GRANT for f in findings)


def test_detect_unencrypted_at_rest() -> None:
    db = DatabaseSecurity(
        encryption_at_rest=False, encryption_in_transit=True,
        auth_mode=AuthMode.MUTUAL_TLS,
    )
    a = _asset(db=db)
    f = detect_unencrypted_at_rest(a, at=_t0())
    assert f is not None and f.kind is DataBreakKind.UNENCRYPTED_AT_REST


def test_detect_backup_missing_none() -> None:
    a = _asset(backup=None)
    f = detect_backup_missing(a, at=_t0())
    assert f is not None and f.kind is DataBreakKind.BACKUP_MISSING


def test_detect_backup_stale() -> None:
    old = _t0() - timedelta(hours=10)
    b = BackupState(kind=BackupKind.FULL, last_backup_at=old,
                    rpo_seconds=3600)
    a = _asset(backup=b)
    f = detect_backup_missing(a, at=_t0())
    assert f is not None and f.kind is DataBreakKind.BACKUP_MISSING


def test_detect_recovery_untested_missing() -> None:
    r = RecoveryState(last_restore_test_at=None)
    a = _asset(recovery=r)
    f = detect_recovery_untested(a, at=_t0())
    assert f is not None and f.kind is DataBreakKind.RECOVERY_UNTESTED


def test_detect_recovery_failed_test() -> None:
    r = RecoveryState(last_restore_test_at=_t0(),
                      last_restore_test_success=False)
    a = _asset(recovery=r)
    f = detect_recovery_untested(a, at=_t0())
    assert f is not None and f.severity == 5


def test_detect_replication_lag() -> None:
    integ = DataIntegrityState(
        checksum_verified_at=_t0(), checksum_verified=True,
        replication_lag_seconds=400,
    )
    a = _asset(integrity=integ)
    f = detect_replication_divergence(a, at=_t0())
    assert f is not None and f.kind is DataBreakKind.REPLICATION_DIVERGENCE


def test_detect_integrity_never_verified() -> None:
    integ = DataIntegrityState(
        checksum_verified_at=None, checksum_verified=False,
    )
    a = _asset(integrity=integ)
    f = detect_integrity_failure(a, at=_t0())
    assert f is not None and f.kind is DataBreakKind.INTEGRITY_FAILURE


def test_detect_access_path_overreach() -> None:
    a = _asset()
    path = DataAccessPath(
        principal_id="u", role_name="r", resource_id=a.asset_id,
        capabilities=frozenset({"select", "ddl"}),
        granted_at=_t0(),
    )
    findings = detect_access_path_overreach(
        a, access_paths=(path,), at=_t0(),
    )
    assert any(f.kind is DataBreakKind.ACCESS_PATH_OVERREACH
               for f in findings)


def test_detect_dependency_discontinuity() -> None:
    g = DataDependencyGraph()
    a = _asset("db1")
    g.add(DataDependencyEdge("app", "db1", "read", 1.0))
    findings = detect_dependency_discontinuity(
        g, "db1", known_entities=frozenset({"db1"}), at=_t0(),
    )
    assert any(f.kind is DataBreakKind.DEPENDENCY_DISCONTINUITY
               for f in findings)


# ---- continuity -----------------------------------------------------------

def test_effective_data_trust_no_constraints() -> None:
    c = effective_data_trust(
        observed=0.9, dependency_scores=[], intrinsic_risk=0.0,
        findings=[],
    )
    assert c == 0.9


def test_effective_data_trust_dependency_ceiling() -> None:
    c = effective_data_trust(
        observed=0.95, dependency_scores=[0.2], intrinsic_risk=0.0,
        findings=[],
    )
    assert c <= 0.2 + TRUST_SLACK + 1e-9


def test_effective_data_trust_intrinsic_risk_halves() -> None:
    c = effective_data_trust(
        observed=1.0, dependency_scores=[], intrinsic_risk=1.0,
        findings=[],
    )
    assert c <= 0.5 + 1e-9


def test_effective_data_trust_findings_penalize() -> None:
    f = DataBreakFinding(
        kind=DataBreakKind.INTEGRITY_FAILURE, asset_id="a",
        detail="x", severity=4, at=_t0(),
    )
    c = effective_data_trust(
        observed=1.0, dependency_scores=[], intrinsic_risk=0.0,
        findings=[f],
    )
    assert c < 1.0


# ---- transition tests -----------------------------------------------------

def test_transition_compromise_to_trusted_rejected() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="a", from_label=TrustLabel.COMPROMISED,
        to_label=TrustLabel.TRUSTED, reason="x", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


def test_transition_quarantine_recovery_requires_verification() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="a", from_label=TrustLabel.QUARANTINED,
        to_label=TrustLabel.OBSERVED, reason="x", verified=False,
    ))
    assert d.outcome is TransitionOutcome.REQUIRES_VERIFICATION


def test_transition_reason_required() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="a", from_label=TrustLabel.OBSERVED,
        to_label=TrustLabel.TRUSTED, reason="", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


# ---- engine integration ---------------------------------------------------

def test_engine_clean_asset_no_violations() -> None:
    eng = StorageDatabaseStateEngine()
    eng.register_asset(_asset("db1"))
    eng.observe_signal("db1", _pos())
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_engine_untrusted_public_exposure_violation() -> None:
    eng = StorageDatabaseStateEngine()
    eng.register_asset(_asset("db1", db=_secure_db(public=True)))
    eng.observe_signal("db1", _pos())
    eng.recompute(at=_t0())
    # Public exposure forces SUSPICIOUS at least, so invariant about
    # TRUSTED with public exposure doesn't fire — but the asset
    # shouldn't be TRUSTED.
    assert eng.label("db1") in (TrustLabel.SUSPICIOUS,
                                TrustLabel.COMPROMISED,
                                TrustLabel.QUARANTINED)


def test_engine_trusted_with_wildcard_role_violation() -> None:
    """A TRUSTED asset with dangerous role triggers invariant."""
    eng = StorageDatabaseStateEngine()
    eng.register_asset(_asset("db1", roles=(
        RoleGrant(role_name="dba", capabilities=frozenset({"select"}),
                  superuser=True),
    )))
    eng.observe_signal("db1", _pos())
    eng.recompute(at=_t0())
    # Superuser finding is severity 5, so it can't be TRUSTED; but the
    # invariant checks the invariant rule anyway.
    v = eng.violations()
    # Either asset is not TRUSTED (correct defense) or invariant fires.
    label = eng.label("db1")
    assert label is not TrustLabel.TRUSTED or any(
        x.invariant_id == "data.no_trusted_with_wildcard_grant" for x in v
    )


def test_engine_high_sensitivity_unencrypted_invariant() -> None:
    eng = StorageDatabaseStateEngine()
    db = DatabaseSecurity(encryption_at_rest=False,
                          encryption_in_transit=True,
                          auth_mode=AuthMode.MUTUAL_TLS)
    eng.register_asset(_asset("db1", sensitivity=0.9, db=db))
    eng.observe_signal("db1", _pos())
    eng.recompute(at=_t0())
    assert any(v.invariant_id == "data.high_sensitivity_unencrypted"
               for v in eng.violations())


def test_engine_trusted_requires_backup_invariant() -> None:
    eng = StorageDatabaseStateEngine()
    eng.register_asset(_asset("db1", backup=None))
    eng.observe_signal("db1", _pos())
    eng.recompute(at=_t0())
    # Either the asset isn't TRUSTED (backup missing is a finding)
    # or the invariant fires.
    v = eng.violations()
    label = eng.label("db1")
    assert label is not TrustLabel.TRUSTED or any(
        x.invariant_id == "data.trusted_requires_backup" for x in v
    )


def test_engine_replica_of_untrusted_primary_violation() -> None:
    eng = StorageDatabaseStateEngine()
    eng.register_asset(_asset("primary"))
    eng.register_asset(_asset("replica", parent="primary"))
    eng.observe_signal("primary", _neg())
    eng.observe_signal("replica", _pos())
    eng.recompute(at=_t0())
    # primary is untrusted, replica should not be TRUSTED
    assert eng.label("replica") is not TrustLabel.TRUSTED or any(
        v.invariant_id == "data.trusted_replica_of_untrusted_primary"
        for v in eng.violations()
    )


def test_engine_access_path_on_untrusted_asset_invariant() -> None:
    eng = StorageDatabaseStateEngine()
    eng.register_asset(_asset("db1"))
    eng.observe_signal("db1", _neg(sid="s1"))
    eng.observe_signal("db1", _neg(sid="s2"))
    eng.grant_access(DataAccessPath(
        principal_id="app", role_name="reader",
        resource_id="db1",
        capabilities=frozenset({"select"}),
        granted_at=_t0(),
    ))
    eng.recompute(at=_t0())
    assert any(v.invariant_id == "data.access_path_on_untrusted_asset"
               for v in eng.violations())


def test_engine_dependency_graph_rejects_unknown() -> None:
    eng = StorageDatabaseStateEngine()
    eng.register_asset(_asset("db1"))
    try:
        eng.add_dependency(DataDependencyEdge(
            "unregistered_app", "db1", "read", 1.0,
        ))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_access_path_unknown_asset_rejected() -> None:
    eng = StorageDatabaseStateEngine()
    try:
        eng.grant_access(DataAccessPath(
            principal_id="app", role_name="reader",
            resource_id="missing", capabilities=frozenset({"select"}),
            granted_at=_t0(),
        ))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_signal_unknown_asset_rejected() -> None:
    eng = StorageDatabaseStateEngine()
    try:
        eng.observe_signal("missing", _pos())
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_revoke_access_path() -> None:
    eng = StorageDatabaseStateEngine()
    eng.register_asset(_asset("db1"))
    eng.grant_access(DataAccessPath(
        principal_id="app", role_name="reader", resource_id="db1",
        capabilities=frozenset({"select"}), granted_at=_t0(),
    ))
    eng.revoke_access("app", "reader", "db1")
    assert eng.snapshot().access_paths == ()


# ---- store tests ----------------------------------------------------------

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryDataStateStore()
    t = _t0()
    s.put(AssetStateRecord("a", TrustLabel.TRUSTED, 0.9, 0, t))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(AssetStateRecord("a", TrustLabel.UNKNOWN, 0.5, 0, earlier))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_in_memory_access_path_store_rejects_stale() -> None:
    s = InMemoryDataStateStore()
    t = _t0()
    p1 = DataAccessPath(
        principal_id="u", role_name="r", resource_id="a",
        capabilities=frozenset({"select"}), granted_at=t,
    )
    s.put_access_path(p1)
    earlier = t.replace(year=t.year - 1)
    try:
        s.put_access_path(DataAccessPath(
            principal_id="u", role_name="r", resource_id="a",
            capabilities=frozenset({"select"}), granted_at=earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_asset_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "data.db")
    store = SqliteDataStateStore(db)
    t = _t0()
    store.put(AssetStateRecord("db1", TrustLabel.TRUSTED, 0.9, 1, t))
    got = store.get("db1")
    assert got is not None and got.label is TrustLabel.TRUSTED


def test_sqlite_store_access_path_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "data.db")
    store = SqliteDataStateStore(db)
    path = DataAccessPath(
        principal_id="app", role_name="reader", resource_id="db1",
        capabilities=frozenset({"select"}),
        granted_at=_t0(),
        expires_at=_t0() + timedelta(days=30),
    )
    store.put_access_path(path)
    got = store.all_access_paths()
    assert len(got) == 1
    assert got[0].capabilities == path.capabilities


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
