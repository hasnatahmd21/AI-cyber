"""
HYDRA™ — Phase 17
Cyber Regeneration Engine

STRICT SCOPE
------------
- Compromise isolation
- Evidence preservation
- Trusted-state discovery
- Authority revocation references
- Reconstruction planning
- Recovery planning
- Integrity verification gates
- Controlled reintroduction
- Regeneration state machine
- Regeneration history
- Failure containment
- Regeneration integrity
- Validation
- Tests

NOT IMPLEMENTED
---------------
Phase 18 -> Adaptive Defense Engine
Phase 19 -> AI/Agent Self-Protection
Phase 20 -> Multi-Layer Defense Fabric
Phase 21 -> Resource & Availability Resilience
Phase 22 -> Full Autonomous Security Control Loop
Phase 23 -> Adversarial Validation
Phase 24 -> Scientific Benchmarking
Phase 25+ -> Enterprise/Production hardening

IMPORTANT
---------
This is a defensive regeneration CONTROL ENGINE.

It does NOT:
- execute arbitrary shell commands
- deploy malware
- attack systems
- modify production infrastructure directly
- automatically grant privileges
- fabricate successful recovery
- declare regeneration successful without verification
"""


from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple
import hashlib
import unittest


# ============================================================================
# HELPERS
# ============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value


def stable_hash(*parts: object) -> str:
    material = "|".join(str(part) for part in parts)
    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


# ============================================================================
# ENUMS
# ============================================================================

class RegenerationStatus(str, Enum):
    CREATED = "CREATED"
    ISOLATING = "ISOLATING"
    ISOLATED = "ISOLATED"
    EVIDENCE_PRESERVED = "EVIDENCE_PRESERVED"
    TRUSTED_STATE_DISCOVERED = "TRUSTED_STATE_DISCOVERED"
    AUTHORITY_REVOKED = "AUTHORITY_REVOKED"
    RECONSTRUCTION_READY = "RECONSTRUCTION_READY"
    RECONSTRUCTED = "RECONSTRUCTED"
    RECOVERY_READY = "RECOVERY_READY"
    RECOVERED = "RECOVERED"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    REINTRODUCTION_READY = "REINTRODUCTION_READY"
    REINTRODUCED = "REINTRODUCED"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class RegenerationPhase(str, Enum):
    ISOLATION = "ISOLATION"
    EVIDENCE_PRESERVATION = "EVIDENCE_PRESERVATION"
    TRUSTED_STATE_DISCOVERY = "TRUSTED_STATE_DISCOVERY"
    AUTHORITY_REVOCATION = "AUTHORITY_REVOCATION"
    RECONSTRUCTION = "RECONSTRUCTION"
    RECOVERY = "RECOVERY"
    INTEGRITY_VERIFICATION = "INTEGRITY_VERIFICATION"
    CONTROLLED_REINTRODUCTION = "CONTROLLED_REINTRODUCTION"


class IsolationStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    REQUESTED = "REQUESTED"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"


class EvidencePreservationStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    REQUESTED = "REQUESTED"
    PRESERVED = "PRESERVED"
    FAILED = "FAILED"


class TrustStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    CANDIDATE = "CANDIDATE"
    TRUSTED = "TRUSTED"
    REJECTED = "REJECTED"


class AuthorityStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    IDENTIFIED = "IDENTIFIED"
    REVOKED = "REVOKED"
    FAILED = "FAILED"


class ReconstructionStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RecoveryStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class IntegrityStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    PASSED = "PASSED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ReintroductionStatus(str, Enum):
    NOT_READY = "NOT_READY"
    READY = "READY"
    APPROVED = "APPROVED"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"


class VerificationResult(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


# ============================================================================
# COMPROMISED ASSET
# ============================================================================

@dataclass(frozen=True)
class CompromisedAsset:
    asset_id: str
    scope_id: str

    asset_type: str

    compromise_reference: str

    detected_at: datetime

    criticality: int = 5

    def __post_init__(self) -> None:

        ensure_aware(self.detected_at)

        if not self.asset_id.strip():
            raise ValueError("asset_id must not be empty")

        if not self.scope_id.strip():
            raise ValueError("scope_id must not be empty")

        if not self.asset_type.strip():
            raise ValueError("asset_type must not be empty")

        if not self.compromise_reference.strip():
            raise ValueError(
                "compromise_reference must not be empty"
            )

        if not 0 <= self.criticality <= 10:
            raise ValueError(
                "criticality must be between 0 and 10"
            )


# ============================================================================
# ISOLATION RECORD
# ============================================================================

@dataclass(frozen=True)
class IsolationRecord:
    isolation_id: str
    scope_id: str
    asset_id: str

    requested_at: datetime

    status: IsolationStatus

    isolation_reference: str

    reason: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.requested_at)

        if not self.isolation_id.strip():
            raise ValueError(
                "isolation_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.asset_id.strip():
            raise ValueError(
                "asset_id must not be empty"
            )

        if not self.isolation_reference.strip():
            raise ValueError(
                "isolation_reference must not be empty"
            )


# ============================================================================
# EVIDENCE PRESERVATION
# ============================================================================

@dataclass(frozen=True)
class EvidencePreservationRecord:
    preservation_id: str
    scope_id: str
    asset_id: str

    requested_at: datetime

    status: EvidencePreservationStatus

    evidence_references: FrozenSet[str]

    preservation_hash: str

    reason: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.requested_at)

        if not self.preservation_id.strip():
            raise ValueError(
                "preservation_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.asset_id.strip():
            raise ValueError(
                "asset_id must not be empty"
            )

        if not self.preservation_hash.strip():
            raise ValueError(
                "preservation_hash must not be empty"
            )


# ============================================================================
# TRUSTED STATE CANDIDATE
# ============================================================================

@dataclass(frozen=True)
class TrustedStateCandidate:
    state_candidate_id: str
    scope_id: str
    asset_id: str

    state_reference: str

    discovered_at: datetime

    status: TrustStatus

    integrity_reference: str

    evidence_references: FrozenSet[str]

    confidence: float

    reason: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.discovered_at)

        if not self.state_candidate_id.strip():
            raise ValueError(
                "state_candidate_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.asset_id.strip():
            raise ValueError(
                "asset_id must not be empty"
            )

        if not self.state_reference.strip():
            raise ValueError(
                "state_reference must not be empty"
            )

        if not self.integrity_reference.strip():
            raise ValueError(
                "integrity_reference must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )


# ============================================================================
# AUTHORITY REVOCATION
# ============================================================================

@dataclass(frozen=True)
class AuthorityRevocationRecord:
    revocation_id: str
    scope_id: str
    asset_id: str

    authority_references: FrozenSet[str]

    requested_at: datetime

    status: AuthorityStatus

    reason: str

    def __post_init__(self) -> None:

        ensure_aware(self.requested_at)

        if not self.revocation_id.strip():
            raise ValueError(
                "revocation_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.asset_id.strip():
            raise ValueError(
                "asset_id must not be empty"
            )

        if not self.reason.strip():
            raise ValueError(
                "revocation reason must not be empty"
            )


# ============================================================================
# RECONSTRUCTION PLAN
# ============================================================================

@dataclass(frozen=True)
class ReconstructionPlan:
    reconstruction_id: str

    scope_id: str
    asset_id: str

    trusted_state_candidate_id: str

    created_at: datetime

    status: ReconstructionStatus

    component_references: Tuple[str, ...]

    integrity_requirements: Tuple[str, ...]

    plan_hash: str

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.reconstruction_id.strip():
            raise ValueError(
                "reconstruction_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.asset_id.strip():
            raise ValueError(
                "asset_id must not be empty"
            )

        if not self.trusted_state_candidate_id.strip():
            raise ValueError(
                "trusted state candidate required"
            )

        if not self.plan_hash.strip():
            raise ValueError(
                "plan_hash must not be empty"
            )


# ============================================================================
# RECOVERY PLAN
# ============================================================================

@dataclass(frozen=True)
class RecoveryPlan:
    recovery_id: str

    scope_id: str
    asset_id: str

    reconstruction_id: str

    created_at: datetime

    status: RecoveryStatus

    recovery_steps: Tuple[str, ...]

    required_verifications: Tuple[str, ...]

    recovery_hash: str

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.recovery_id.strip():
            raise ValueError(
                "recovery_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.asset_id.strip():
            raise ValueError(
                "asset_id must not be empty"
            )

        if not self.reconstruction_id.strip():
            raise ValueError(
                "reconstruction_id must not be empty"
            )

        if not self.recovery_hash.strip():
            raise ValueError(
                "recovery_hash must not be empty"
            )


# ============================================================================
# INTEGRITY CHECK
# ============================================================================

@dataclass(frozen=True)
class IntegrityCheck:
    check_id: str

    scope_id: str
    asset_id: str

    check_type: str

    expected_reference: str
    observed_reference: str

    checked_at: datetime

    result: IntegrityStatus

    confidence: float

    reason: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.checked_at)

        if not self.check_id.strip():
            raise ValueError(
                "check_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.asset_id.strip():
            raise ValueError(
                "asset_id must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1"
            )


# ============================================================================
# REINTRODUCTION RECORD
# ============================================================================

@dataclass(frozen=True)
class ControlledReintroduction:
    reintroduction_id: str

    scope_id: str
    asset_id: str

    requested_at: datetime

    status: ReintroductionStatus

    integrity_check_ids: FrozenSet[str]

    approval_reference: Optional[str]

    reason: str = ""

    def __post_init__(self) -> None:

        ensure_aware(self.requested_at)

        if not self.reintroduction_id.strip():
            raise ValueError(
                "reintroduction_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )

        if not self.asset_id.strip():
            raise ValueError(
                "asset_id must not be empty"
            )


# ============================================================================
# REGENERATION RECORD
# ============================================================================

@dataclass
class RegenerationRecord:

    regeneration_id: str
    scope_id: str

    created_at: datetime

    status: RegenerationStatus = (
        RegenerationStatus.CREATED
    )

    asset_ids: Tuple[str, ...] = ()

    isolation_ids: Tuple[str, ...] = ()

    preservation_ids: Tuple[str, ...] = ()

    trusted_state_ids: Tuple[str, ...] = ()

    revocation_ids: Tuple[str, ...] = ()

    reconstruction_ids: Tuple[str, ...] = ()

    recovery_ids: Tuple[str, ...] = ()

    integrity_check_ids: Tuple[str, ...] = ()

    reintroduction_ids: Tuple[str, ...] = ()

    failure_reason: Optional[str] = None

    regeneration_hash: Optional[str] = None

    def __post_init__(self) -> None:

        ensure_aware(self.created_at)

        if not self.regeneration_id.strip():
            raise ValueError(
                "regeneration_id must not be empty"
            )

        if not self.scope_id.strip():
            raise ValueError(
                "scope_id must not be empty"
            )


# ============================================================================
# REGENERATION ENGINE
# ============================================================================

class CyberRegenerationEngine:

    def __init__(
        self,
        *,
        minimum_trusted_state_confidence: float = 0.80,
        minimum_integrity_confidence: float = 0.80,
    ) -> None:

        if not (
            0.0
            <= minimum_trusted_state_confidence
            <= 1.0
        ):
            raise ValueError(
                "invalid trusted-state threshold"
            )

        if not (
            0.0
            <= minimum_integrity_confidence
            <= 1.0
        ):
            raise ValueError(
                "invalid integrity threshold"
            )

        self.minimum_trusted_state_confidence = (
            minimum_trusted_state_confidence
        )

        self.minimum_integrity_confidence = (
            minimum_integrity_confidence
        )

        self._assets: Dict[
            str,
            CompromisedAsset,
        ] = {}

        self._isolations: Dict[
            str,
            IsolationRecord,
        ] = {}

        self._preservations: Dict[
            str,
            EvidencePreservationRecord,
        ] = {}

        self._trusted_states: Dict[
            str,
            TrustedStateCandidate,
        ] = {}

        self._revocations: Dict[
            str,
            AuthorityRevocationRecord,
        ] = {}

        self._reconstructions: Dict[
            str,
            ReconstructionPlan,
        ] = {}

        self._recoveries: Dict[
            str,
            RecoveryPlan,
        ] = {}

        self._integrity_checks: Dict[
            str,
            IntegrityCheck,
        ] = {}

        self._reintroductions: Dict[
            str,
            ControlledReintroduction,
        ] = {}

        self._regenerations: Dict[
            str,
            RegenerationRecord,
        ] = {}

        self._lock = RLock()

    # ========================================================================
    # ASSET REGISTRATION
    # ========================================================================

    def add_asset(
        self,
        asset: CompromisedAsset,
    ) -> None:

        with self._lock:

            if asset.asset_id in self._assets:
                raise ValueError(
                    "duplicate compromised asset"
                )

            self._assets[
                asset.asset_id
            ] = asset

    # ========================================================================
    # REGENERATION CREATION
    # ========================================================================

    def create_regeneration(
        self,
        *,
        regeneration_id: str,
        scope_id: str,
        asset_ids: Iterable[str],
    ) -> RegenerationRecord:

        asset_ids = tuple(asset_ids)

        if not asset_ids:
            raise ValueError(
                "at least one asset is required"
            )

        with self._lock:

            if regeneration_id in self._regenerations:
                raise ValueError(
                    "duplicate regeneration"
                )

            for asset_id in asset_ids:

                asset = self._assets.get(
                    asset_id
                )

                if asset is None:
                    raise KeyError(
                        f"asset not found: {asset_id}"
                    )

                if asset.scope_id != scope_id:
                    raise ValueError(
                        "asset scope mismatch"
                    )

            record = RegenerationRecord(
                regeneration_id=regeneration_id,
                scope_id=scope_id,
                created_at=utc_now(),
                asset_ids=asset_ids,
            )

            self._regenerations[
                regeneration_id
            ] = record

            self._refresh_hash(record)

            return record

    def get_regeneration(
        self,
        regeneration_id: str,
    ) -> RegenerationRecord:

        with self._lock:

            record = self._regenerations.get(
                regeneration_id
            )

            if record is None:
                raise KeyError(
                    "regeneration not found"
                )

            return record

    # ========================================================================
    # ISOLATION
    # ========================================================================

    def isolate_asset(
        self,
        regeneration_id: str,
        asset_id: str,
        *,
        isolation_reference: str,
        confirmed: bool,
        reason: str,
    ) -> IsolationRecord:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            asset = self._assets.get(
                asset_id
            )

            if asset is None:
                raise KeyError(
                    "asset not found"
                )

            if asset.scope_id != regeneration.scope_id:
                raise ValueError(
                    "asset scope mismatch"
                )

            if asset_id not in regeneration.asset_ids:
                raise ValueError(
                    "asset not included in regeneration"
                )

            status = (
                IsolationStatus.CONFIRMED
                if confirmed
                else IsolationStatus.FAILED
            )

            isolation_id = stable_hash(
                "isolation",
                regeneration_id,
                asset_id,
                isolation_reference,
            )

            record = IsolationRecord(
                isolation_id=isolation_id,
                scope_id=regeneration.scope_id,
                asset_id=asset_id,
                requested_at=utc_now(),
                status=status,
                isolation_reference=isolation_reference,
                reason=reason,
            )

            self._isolations[
                isolation_id
            ] = record

            regeneration.isolation_ids = (
                *regeneration.isolation_ids,
                isolation_id,
            )

            if not confirmed:

                regeneration.status = (
                    RegenerationStatus.FAILED
                )

                regeneration.failure_reason = (
                    "asset isolation not confirmed"
                )

            else:

                regeneration.status = (
                    RegenerationStatus.ISOLATED
                )

            self._refresh_hash(regeneration)

            return record

    # ========================================================================
    # EVIDENCE PRESERVATION
    # ========================================================================

    def preserve_evidence(
        self,
        regeneration_id: str,
        asset_id: str,
        *,
        evidence_references: Iterable[str],
        preservation_reference: str,
        preserved: bool,
        reason: str,
    ) -> EvidencePreservationRecord:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            if asset_id not in regeneration.asset_ids:
                raise ValueError(
                    "asset not included in regeneration"
                )

            evidence_references = frozenset(
                evidence_references
            )

            preservation_hash = stable_hash(
                "evidence-preservation",
                regeneration_id,
                asset_id,
                sorted(evidence_references),
                preservation_reference,
            )

            status = (
                EvidencePreservationStatus.PRESERVED
                if preserved
                else EvidencePreservationStatus.FAILED
            )

            record = EvidencePreservationRecord(
                preservation_id=stable_hash(
                    "preservation",
                    regeneration_id,
                    asset_id,
                    preservation_reference,
                ),
                scope_id=regeneration.scope_id,
                asset_id=asset_id,
                requested_at=utc_now(),
                status=status,
                evidence_references=evidence_references,
                preservation_hash=preservation_hash,
                reason=reason,
            )

            self._preservations[
                record.preservation_id
            ] = record

            regeneration.preservation_ids = (
                *regeneration.preservation_ids,
                record.preservation_id,
            )

            if preserved:

                regeneration.status = (
                    RegenerationStatus.EVIDENCE_PRESERVED
                )

            else:

                regeneration.status = (
                    RegenerationStatus.FAILED
                )

                regeneration.failure_reason = (
                    "evidence preservation failed"
                )

            self._refresh_hash(regeneration)

            return record

    # ========================================================================
    # TRUSTED STATE DISCOVERY
    # ========================================================================

    def discover_trusted_state(
        self,
        regeneration_id: str,
        asset_id: str,
        *,
        state_reference: str,
        integrity_reference: str,
        evidence_references: Iterable[str],
        confidence: float,
        trusted: bool,
        reason: str,
    ) -> TrustedStateCandidate:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            if asset_id not in regeneration.asset_ids:
                raise ValueError(
                    "asset not included in regeneration"
                )

            if not 0.0 <= confidence <= 1.0:
                raise ValueError(
                    "confidence must be between 0 and 1"
                )

            if (
                trusted
                and confidence
                < self.minimum_trusted_state_confidence
            ):
                raise ValueError(
                    "trusted state confidence below threshold"
                )

            status = (
                TrustStatus.TRUSTED
                if trusted
                else TrustStatus.REJECTED
            )

            candidate = TrustedStateCandidate(
                state_candidate_id=stable_hash(
                    "trusted-state",
                    regeneration_id,
                    asset_id,
                    state_reference,
                ),
                scope_id=regeneration.scope_id,
                asset_id=asset_id,
                state_reference=state_reference,
                discovered_at=utc_now(),
                status=status,
                integrity_reference=integrity_reference,
                evidence_references=frozenset(
                    evidence_references
                ),
                confidence=confidence,
                reason=reason,
            )

            self._trusted_states[
                candidate.state_candidate_id
            ] = candidate

            if trusted:

                regeneration.trusted_state_ids = (
                    *regeneration.trusted_state_ids,
                    candidate.state_candidate_id,
                )

                regeneration.status = (
                    RegenerationStatus.TRUSTED_STATE_DISCOVERED
                )

            self._refresh_hash(regeneration)

            return candidate

    # ========================================================================
    # AUTHORITY REVOCATION
    # ========================================================================

    def revoke_authority(
        self,
        regeneration_id: str,
        asset_id: str,
        *,
        authority_references: Iterable[str],
        revocation_reference: str,
        revoked: bool,
        reason: str,
    ) -> AuthorityRevocationRecord:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            if asset_id not in regeneration.asset_ids:
                raise ValueError(
                    "asset not included in regeneration"
                )

            authority_references = frozenset(
                authority_references
            )

            status = (
                AuthorityStatus.REVOKED
                if revoked
                else AuthorityStatus.FAILED
            )

            record = AuthorityRevocationRecord(
                revocation_id=stable_hash(
                    "revocation",
                    regeneration_id,
                    asset_id,
                    revocation_reference,
                ),
                scope_id=regeneration.scope_id,
                asset_id=asset_id,
                authority_references=authority_references,
                requested_at=utc_now(),
                status=status,
                reason=reason,
            )

            self._revocations[
                record.revocation_id
            ] = record

            regeneration.revocation_ids = (
                *regeneration.revocation_ids,
                record.revocation_id,
            )

            if revoked:

                regeneration.status = (
                    RegenerationStatus.AUTHORITY_REVOKED
                )

            else:

                regeneration.status = (
                    RegenerationStatus.FAILED
                )

                regeneration.failure_reason = (
                    "authority revocation failed"
                )

            self._refresh_hash(regeneration)

            return record

    # ========================================================================
    # RECONSTRUCTION
    # ========================================================================

    def create_reconstruction_plan(
        self,
        regeneration_id: str,
        asset_id: str,
        *,
        trusted_state_candidate_id: str,
        component_references: Iterable[str],
        integrity_requirements: Iterable[str],
    ) -> ReconstructionPlan:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            candidate = self._trusted_states.get(
                trusted_state_candidate_id
            )

            if candidate is None:
                raise KeyError(
                    "trusted state candidate not found"
                )

            if candidate.scope_id != regeneration.scope_id:
                raise ValueError(
                    "trusted state scope mismatch"
                )

            if candidate.asset_id != asset_id:
                raise ValueError(
                    "trusted state asset mismatch"
                )

            if candidate.status != TrustStatus.TRUSTED:
                raise ValueError(
                    "state candidate is not trusted"
                )

            component_references = tuple(
                component_references
            )

            integrity_requirements = tuple(
                integrity_requirements
            )

            if not component_references:
                raise ValueError(
                    "reconstruction requires components"
                )

            if not integrity_requirements:
                raise ValueError(
                    "reconstruction requires integrity checks"
                )

            plan_hash = stable_hash(
                "reconstruction-plan",
                regeneration_id,
                asset_id,
                trusted_state_candidate_id,
                component_references,
                integrity_requirements,
            )

            plan = ReconstructionPlan(
                reconstruction_id=stable_hash(
                    "reconstruction",
                    regeneration_id,
                    asset_id,
                    plan_hash,
                ),
                scope_id=regeneration.scope_id,
                asset_id=asset_id,
                trusted_state_candidate_id=(
                    trusted_state_candidate_id
                ),
                created_at=utc_now(),
                status=ReconstructionStatus.PLANNED,
                component_references=component_references,
                integrity_requirements=(
                    integrity_requirements
                ),
                plan_hash=plan_hash,
            )

            self._reconstructions[
                plan.reconstruction_id
            ] = plan

            regeneration.reconstruction_ids = (
                *regeneration.reconstruction_ids,
                plan.reconstruction_id,
            )

            regeneration.status = (
                RegenerationStatus.RECONSTRUCTION_READY
            )

            self._refresh_hash(regeneration)

            return plan

    # ========================================================================
    # RECONSTRUCTION COMPLETION
    # ========================================================================

    def complete_reconstruction(
        self,
        regeneration_id: str,
        reconstruction_id: str,
        *,
        successful: bool,
    ) -> ReconstructionPlan:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            plan = self._reconstructions.get(
                reconstruction_id
            )

            if plan is None:
                raise KeyError(
                    "reconstruction plan not found"
                )

            if plan.scope_id != regeneration.scope_id:
                raise ValueError(
                    "reconstruction scope mismatch"
                )

            if successful:

                updated = ReconstructionPlan(
                    reconstruction_id=plan.reconstruction_id,
                    scope_id=plan.scope_id,
                    asset_id=plan.asset_id,
                    trusted_state_candidate_id=(
                        plan.trusted_state_candidate_id
                    ),
                    created_at=plan.created_at,
                    status=ReconstructionStatus.COMPLETED,
                    component_references=(
                        plan.component_references
                    ),
                    integrity_requirements=(
                        plan.integrity_requirements
                    ),
                    plan_hash=plan.plan_hash,
                )

                self._reconstructions[
                    reconstruction_id
                ] = updated

                regeneration.status = (
                    RegenerationStatus.RECONSTRUCTED
                )

            else:

                updated = ReconstructionPlan(
                    reconstruction_id=plan.reconstruction_id,
                    scope_id=plan.scope_id,
                    asset_id=plan.asset_id,
                    trusted_state_candidate_id=(
                        plan.trusted_state_candidate_id
                    ),
                    created_at=plan.created_at,
                    status=ReconstructionStatus.FAILED,
                    component_references=(
                        plan.component_references
                    ),
                    integrity_requirements=(
                        plan.integrity_requirements
                    ),
                    plan_hash=plan.plan_hash,
                )

                self._reconstructions[
                    reconstruction_id
                ] = updated

                regeneration.status = (
                    RegenerationStatus.FAILED
                )

                regeneration.failure_reason = (
                    "reconstruction failed"
                )

            self._refresh_hash(regeneration)

            return updated

    # ========================================================================
    # RECOVERY
    # ========================================================================

    def create_recovery_plan(
        self,
        regeneration_id: str,
        asset_id: str,
        *,
        reconstruction_id: str,
        recovery_steps: Iterable[str],
        required_verifications: Iterable[str],
    ) -> RecoveryPlan:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            reconstruction = self._reconstructions.get(
                reconstruction_id
            )

            if reconstruction is None:
                raise KeyError(
                    "reconstruction not found"
                )

            if reconstruction.status != (
                ReconstructionStatus.COMPLETED
            ):
                raise ValueError(
                    "reconstruction must be completed"
                )

            recovery_steps = tuple(
                recovery_steps
            )

            required_verifications = tuple(
                required_verifications
            )

            if not recovery_steps:
                raise ValueError(
                    "recovery requires steps"
                )

            if not required_verifications:
                raise ValueError(
                    "recovery requires verification gates"
                )

            recovery_hash = stable_hash(
                "recovery-plan",
                regeneration_id,
                asset_id,
                reconstruction_id,
                recovery_steps,
                required_verifications,
            )

            plan = RecoveryPlan(
                recovery_id=stable_hash(
                    "recovery",
                    regeneration_id,
                    asset_id,
                    recovery_hash,
                ),
                scope_id=regeneration.scope_id,
                asset_id=asset_id,
                reconstruction_id=reconstruction_id,
                created_at=utc_now(),
                status=RecoveryStatus.PLANNED,
                recovery_steps=recovery_steps,
                required_verifications=(
                    required_verifications
                ),
                recovery_hash=recovery_hash,
            )

            self._recoveries[
                plan.recovery_id
            ] = plan

            regeneration.recovery_ids = (
                *regeneration.recovery_ids,
                plan.recovery_id,
            )

            regeneration.status = (
                RegenerationStatus.RECOVERY_READY
            )

            self._refresh_hash(regeneration)

            return plan

    # ========================================================================
    # RECOVERY COMPLETION
    # ========================================================================

    def complete_recovery(
        self,
        regeneration_id: str,
        recovery_id: str,
        *,
        successful: bool,
    ) -> RecoveryPlan:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            plan = self._recoveries.get(
                recovery_id
            )

            if plan is None:
                raise KeyError(
                    "recovery plan not found"
                )

            if successful:

                updated = RecoveryPlan(
                    recovery_id=plan.recovery_id,
                    scope_id=plan.scope_id,
                    asset_id=plan.asset_id,
                    reconstruction_id=plan.reconstruction_id,
                    created_at=plan.created_at,
                    status=RecoveryStatus.COMPLETED,
                    recovery_steps=(
                        plan.recovery_steps
                    ),
                    required_verifications=(
                        plan.required_verifications
                    ),
                    recovery_hash=plan.recovery_hash,
                )

                self._recoveries[
                    recovery_id
                ] = updated

                regeneration.status = (
                    RegenerationStatus.RECOVERED
                )

            else:

                updated = RecoveryPlan(
                    recovery_id=plan.recovery_id,
                    scope_id=plan.scope_id,
                    asset_id=plan.asset_id,
                    reconstruction_id=plan.reconstruction_id,
                    created_at=plan.created_at,
                    status=RecoveryStatus.FAILED,
                    recovery_steps=(
                        plan.recovery_steps
                    ),
                    required_verifications=(
                        plan.required_verifications
                    ),
                    recovery_hash=plan.recovery_hash,
                )

                self._recoveries[
                    recovery_id
                ] = updated

                regeneration.status = (
                    RegenerationStatus.FAILED
                )

                regeneration.failure_reason = (
                    "recovery failed"
                )

            self._refresh_hash(regeneration)

            return updated

    # ========================================================================
    # INTEGRITY VERIFICATION
    # ========================================================================

    def add_integrity_check(
        self,
        regeneration_id: str,
        check: IntegrityCheck,
    ) -> None:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            if check.scope_id != regeneration.scope_id:
                raise ValueError(
                    "integrity check scope mismatch"
                )

            if check.asset_id not in regeneration.asset_ids:
                raise ValueError(
                    "asset not included in regeneration"
                )

            if check.check_id in self._integrity_checks:
                raise ValueError(
                    "duplicate integrity check"
                )

            self._integrity_checks[
                check.check_id
            ] = check

            regeneration.integrity_check_ids = (
                *regeneration.integrity_check_ids,
                check.check_id,
            )

            self._refresh_hash(regeneration)

    def evaluate_integrity(
        self,
        regeneration_id: str,
    ) -> IntegrityStatus:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            checks = [
                self._integrity_checks[
                    check_id
                ]
                for check_id
                in regeneration.integrity_check_ids
            ]

            if not checks:

                regeneration.status = (
                    RegenerationStatus.FAILED
                )

                regeneration.failure_reason = (
                    "no integrity checks available"
                )

                self._refresh_hash(regeneration)

                return IntegrityStatus.UNKNOWN

            passed = [
                check
                for check
                in checks
                if (
                    check.result
                    == IntegrityStatus.PASSED
                    and check.confidence
                    >= self.minimum_integrity_confidence
                )
            ]

            failed = [
                check
                for check
                in checks
                if check.result
                == IntegrityStatus.FAILED
            ]

            if len(passed) == len(checks):

                regeneration.status = (
                    RegenerationStatus.INTEGRITY_VERIFIED
                )

                self._refresh_hash(regeneration)

                return IntegrityStatus.PASSED

            if failed:

                regeneration.status = (
                    RegenerationStatus.FAILED
                )

                regeneration.failure_reason = (
                    "integrity verification failed"
                )

                self._refresh_hash(regeneration)

                return IntegrityStatus.FAILED

            return IntegrityStatus.PARTIAL

    # ========================================================================
    # CONTROLLED REINTRODUCTION
    # ========================================================================

    def prepare_reintroduction(
        self,
        regeneration_id: str,
        asset_id: str,
        *,
        approval_reference: Optional[str] = None,
    ) -> ControlledReintroduction:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            if asset_id not in regeneration.asset_ids:
                raise ValueError(
                    "asset not included in regeneration"
                )

            if (
                regeneration.status
                != RegenerationStatus.INTEGRITY_VERIFIED
            ):
                return ControlledReintroduction(
                    reintroduction_id=stable_hash(
                        "reintroduction",
                        regeneration_id,
                        asset_id,
                    ),
                    scope_id=regeneration.scope_id,
                    asset_id=asset_id,
                    requested_at=utc_now(),
                    status=ReintroductionStatus.BLOCKED,
                    integrity_check_ids=frozenset(
                        regeneration.integrity_check_ids
                    ),
                    approval_reference=approval_reference,
                    reason=(
                        "integrity verification "
                        "has not passed"
                    ),
                )

            if not approval_reference:

                return ControlledReintroduction(
                    reintroduction_id=stable_hash(
                        "reintroduction",
                        regeneration_id,
                        asset_id,
                    ),
                    scope_id=regeneration.scope_id,
                    asset_id=asset_id,
                    requested_at=utc_now(),
                    status=ReintroductionStatus.NOT_READY,
                    integrity_check_ids=frozenset(
                        regeneration.integrity_check_ids
                    ),
                    approval_reference=None,
                    reason=(
                        "controlled reintroduction "
                        "requires explicit approval reference"
                    ),
                )

            record = ControlledReintroduction(
                reintroduction_id=stable_hash(
                    "reintroduction",
                    regeneration_id,
                    asset_id,
                    approval_reference,
                ),
                scope_id=regeneration.scope_id,
                asset_id=asset_id,
                requested_at=utc_now(),
                status=ReintroductionStatus.READY,
                integrity_check_ids=frozenset(
                    regeneration.integrity_check_ids
                ),
                approval_reference=approval_reference,
                reason=(
                    "integrity verified and "
                    "approval reference supplied"
                ),
            )

            self._reintroductions[
                record.reintroduction_id
            ] = record

            regeneration.reintroduction_ids = (
                *regeneration.reintroduction_ids,
                record.reintroduction_id,
            )

            regeneration.status = (
                RegenerationStatus.REINTRODUCTION_READY
            )

            self._refresh_hash(regeneration)

            return record

    # ========================================================================
    # CONTROLLED REINTRODUCTION COMPLETION
    # ========================================================================

    def complete_reintroduction(
        self,
        regeneration_id: str,
        reintroduction_id: str,
        *,
        successful: bool,
    ) -> ControlledReintroduction:

        with self._lock:

            regeneration = self.get_regeneration(
                regeneration_id
            )

            record = self._reintroductions.get(
                reintroduction_id
            )

            if record is None:
                raise KeyError(
                    "reintroduction not found"
                )

            if (
                record.scope_id
                != regeneration.scope_id
            ):
                raise ValueError(
                    "reintroduction scope mismatch"
                )

            if record.status != (
                ReintroductionStatus.READY
            ):
                raise ValueError(
                    "reintroduction is not READY"
                )

            if successful:

                updated = ControlledReintroduction(
                    reintroduction_id=(
                        record.reintroduction_id
                    ),
                    scope_id=record.scope_id,
                    asset_id=record.asset_id,
                    requested_at=record.requested_at,
                    status=(
                        ReintroductionStatus.COMPLETED
                    ),
                    integrity_check_ids=(
                        record.integrity_check_ids
                    ),
                    approval_reference=(
                        record.approval_reference
                    ),
                    reason=(
                        "controlled reintroduction "
                        "confirmed"
                    ),
                )

                self._reintroductions[
                    reintroduction_id
                ] = updated

                regeneration.status = (
                    RegenerationStatus.COMPLETED
                )

            else:

                updated = ControlledReintroduction(
                    reintroduction_id=(
                        record.reintroduction_id
                    ),
                    scope_id=record.scope_id,
                    asset_id=record.asset_id,
                    requested_at=record.requested_at,
                    status=(
                        ReintroductionStatus.BLOCKED
                    ),
                    integrity_check_ids=(
                        record.integrity_check_ids
                    ),
                    approval_reference=(
                        record.approval_reference
                    ),
                    reason=(
                        "controlled reintroduction failed"
                    ),
                )

                self._reintroductions[
                    reintroduction_id
                ] = updated

                regeneration.status = (
                    RegenerationStatus.FAILED
                )

                regeneration.failure_reason = (
                    "reintroduction failed"
                )

            self._refresh_hash(regeneration)

            return updated

    # ========================================================================
    # REGENERATION HASH
    # ========================================================================

    @staticmethod
    def _hash_material(
        record: RegenerationRecord,
    ) -> Tuple[object, ...]:

        return (
            record.regeneration_id,
            record.scope_id,
            record.status.value,
            record.asset_ids,
            record.isolation_ids,
            record.preservation_ids,
            record.trusted_state_ids,
            record.revocation_ids,
            record.reconstruction_ids,
            record.recovery_ids,
            record.integrity_check_ids,
            record.reintroduction_ids,
            record.failure_reason,
        )

    def _refresh_hash(
        self,
        record: RegenerationRecord,
    ) -> None:

        record.regeneration_hash = stable_hash(
            *self._hash_material(record)
        )

    @classmethod
    def validate_regeneration_hash(
        cls,
        record: RegenerationRecord,
    ) -> bool:

        if not record.regeneration_hash:
            return False

        return (
            record.regeneration_hash
            == stable_hash(
                *cls._hash_material(record)
            )
        )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> List[str]:

        errors: List[str] = []

        with self._lock:

            for asset_id, asset in self._assets.items():

                if asset_id != asset.asset_id:
                    errors.append(
                        f"asset key mismatch: {asset_id}"
                    )

            for record_id, record in (
                self._regenerations.items()
            ):

                if record_id != record.regeneration_id:
                    errors.append(
                        f"regeneration key mismatch: "
                        f"{record_id}"
                    )

                if not self.validate_regeneration_hash(
                    record
                ):
                    errors.append(
                        f"regeneration hash mismatch: "
                        f"{record_id}"
                    )

                for asset_id in record.asset_ids:

                    asset = self._assets.get(
                        asset_id
                    )

                    if asset is None:
                        errors.append(
                            f"unknown regeneration asset: "
                            f"{asset_id}"
                        )

                    elif asset.scope_id != record.scope_id:
                        errors.append(
                            f"regeneration asset scope mismatch: "
                            f"{asset_id}"
                        )

                for isolation_id in (
                    record.isolation_ids
                ):

                    isolation = self._isolations.get(
                        isolation_id
                    )

                    if isolation is None:
                        errors.append(
                            f"unknown isolation: "
                            f"{isolation_id}"
                        )

                    elif isolation.scope_id != record.scope_id:
                        errors.append(
                            f"isolation scope mismatch: "
                            f"{isolation_id}"
                        )

                for preservation_id in (
                    record.preservation_ids
                ):

                    preservation = self._preservations.get(
                        preservation_id
                    )

                    if preservation is None:
                        errors.append(
                            f"unknown preservation: "
                            f"{preservation_id}"
                        )

                for state_id in (
                    record.trusted_state_ids
                ):

                    state = self._trusted_states.get(
                        state_id
                    )

                    if state is None:
                        errors.append(
                            f"unknown trusted state: "
                            f"{state_id}"
                        )

                    elif state.status != TrustStatus.TRUSTED:
                        errors.append(
                            f"non-trusted state referenced: "
                            f"{state_id}"
                        )

                for revocation_id in (
                    record.revocation_ids
                ):

                    revocation = self._revocations.get(
                        revocation_id
                    )

                    if revocation is None:
                        errors.append(
                            f"unknown revocation: "
                            f"{revocation_id}"
                        )

                for reconstruction_id in (
                    record.reconstruction_ids
                ):

                    reconstruction = (
                        self._reconstructions.get(
                            reconstruction_id
                        )
                    )

                    if reconstruction is None:
                        errors.append(
                            f"unknown reconstruction: "
                            f"{reconstruction_id}"
                        )

                for recovery_id in (
                    record.recovery_ids
                ):

                    recovery = self._recoveries.get(
                        recovery_id
                    )

                    if recovery is None:
                        errors.append(
                            f"unknown recovery: "
                            f"{recovery_id}"
                        )

                for check_id in (
                    record.integrity_check_ids
                ):

                    check = self._integrity_checks.get(
                        check_id
                    )

                    if check is None:
                        errors.append(
                            f"unknown integrity check: "
                            f"{check_id}"
                        )

                for reintroduction_id in (
                    record.reintroduction_ids
                ):

                    reintroduction = (
                        self._reintroductions.get(
                            reintroduction_id
                        )
                    )

                    if reintroduction is None:
                        errors.append(
                            f"unknown reintroduction: "
                            f"{reintroduction_id}"
                        )

        return errors


# ============================================================================
# TESTS
# ============================================================================

class Phase17Tests(unittest.TestCase):

    def setUp(self):

        self.engine = CyberRegenerationEngine()

        self.asset = CompromisedAsset(
            asset_id="endpoint-1",
            scope_id="scope-a",
            asset_type="endpoint",
            compromise_reference="incident-1",
            detected_at=utc_now(),
            criticality=8,
        )

        self.engine.add_asset(
            self.asset
        )

        self.regeneration = (
            self.engine.create_regeneration(
                regeneration_id="regen-1",
                scope_id="scope-a",
                asset_ids=("endpoint-1",),
            )
        )

    # ========================================================================
    # Creation
    # ========================================================================

    def test_regeneration_creation(self):

        self.assertEqual(
            self.regeneration.status,
            RegenerationStatus.CREATED,
        )

        self.assertTrue(
            self.engine.validate_regeneration_hash(
                self.regeneration
            )
        )

    # ========================================================================
    # Isolation
    # ========================================================================

    def test_isolation(self):

        record = self.engine.isolate_asset(
            "regen-1",
            "endpoint-1",
            isolation_reference="isolation-op-1",
            confirmed=True,
            reason="compromise containment",
        )

        self.assertEqual(
            record.status,
            IsolationStatus.CONFIRMED,
        )

        self.assertEqual(
            self.regeneration.status,
            RegenerationStatus.ISOLATED,
        )

    # ========================================================================
    # Failed isolation
    # ========================================================================

    def test_failed_isolation_blocks_regeneration(self):

        self.engine.isolate_asset(
            "regen-1",
            "endpoint-1",
            isolation_reference="isolation-failed",
            confirmed=False,
            reason="not confirmed",
        )

        self.assertEqual(
            self.regeneration.status,
            RegenerationStatus.FAILED,
        )

        self.assertIsNotNone(
            self.regeneration.failure_reason
        )

    # ========================================================================
    # Evidence preservation
    # ========================================================================

    def test_evidence_preservation(self):

        self.engine.isolate_asset(
            "regen-1",
            "endpoint-1",
            isolation_reference="iso",
            confirmed=True,
            reason="containment",
        )

        preservation = (
            self.engine.preserve_evidence(
                "regen-1",
                "endpoint-1",
                evidence_references=(
                    "evidence-1",
                    "evidence-2",
                ),
                preservation_reference="vault-1",
                preserved=True,
                reason="evidence secured",
            )
        )

        self.assertEqual(
            preservation.status,
            EvidencePreservationStatus.PRESERVED,
        )

        self.assertEqual(
            self.regeneration.status,
            RegenerationStatus.EVIDENCE_PRESERVED,
        )

    # ========================================================================
    # Trusted state
    # ========================================================================

    def test_trusted_state_discovery(self):

        candidate = (
            self.engine.discover_trusted_state(
                "regen-1",
                "endpoint-1",
                state_reference="trusted-state-1",
                integrity_reference="integrity-ref-1",
                evidence_references=(
                    "evidence-1",
                ),
                confidence=0.95,
                trusted=True,
                reason="verified clean state",
            )
        )

        self.assertEqual(
            candidate.status,
            TrustStatus.TRUSTED,
        )

        self.assertEqual(
            self.regeneration.status,
            RegenerationStatus.TRUSTED_STATE_DISCOVERED,
        )

    # ========================================================================
    # Low-confidence trusted state rejected
    # ========================================================================

    def test_low_confidence_trusted_state_rejected(self):

        with self.assertRaises(ValueError):

            self.engine.discover_trusted_state(
                "regen-1",
                "endpoint-1",
                state_reference="weak-state",
                integrity_reference="weak-integrity",
                evidence_references=(),
                confidence=0.50,
                trusted=True,
                reason="insufficient evidence",
            )

    # ========================================================================
    # Authority revocation
    # ========================================================================

    def test_authority_revocation(self):

        record = (
            self.engine.revoke_authority(
                "regen-1",
                "endpoint-1",
                authority_references=(
                    "agent-1",
                    "token-1",
                ),
                revocation_reference="revoke-op-1",
                revoked=True,
                reason="compromised asset",
            )
        )

        self.assertEqual(
            record.status,
            AuthorityStatus.REVOKED,
        )

        self.assertEqual(
            self.regeneration.status,
            RegenerationStatus.AUTHORITY_REVOKED,
        )

    # ========================================================================
    # Reconstruction
    # ========================================================================

    def test_reconstruction(self):

        candidate = (
            self.engine.discover_trusted_state(
                "regen-1",
                "endpoint-1",
                state_reference="trusted-state",
                integrity_reference="integrity",
                evidence_references=(),
                confidence=0.95,
                trusted=True,
                reason="trusted",
            )
        )

        plan = (
            self.engine.create_reconstruction_plan(
                "regen-1",
                "endpoint-1",
                trusted_state_candidate_id=(
                    candidate.state_candidate_id
                ),
                component_references=(
                    "component-a",
                    "component-b",
                ),
                integrity_requirements=(
                    "hash-check",
                    "config-check",
                ),
            )
        )

        self.assertEqual(
            plan.status,
            ReconstructionStatus.PLANNED,
        )

        completed = (
            self.engine.complete_reconstruction(
                "regen-1",
                plan.reconstruction_id,
                successful=True,
            )
        )

        self.assertEqual(
            completed.status,
            ReconstructionStatus.COMPLETED,
        )

    # ========================================================================
    # Recovery
    # ========================================================================

    def test_recovery(self):

        candidate = (
            self.engine.discover_trusted_state(
                "regen-1",
                "endpoint-1",
                state_reference="trusted-state",
                integrity_reference="integrity",
                evidence_references=(),
                confidence=0.95,
                trusted=True,
                reason="trusted",
            )
        )

        reconstruction = (
            self.engine.create_reconstruction_plan(
                "regen-1",
                "endpoint-1",
                trusted_state_candidate_id=(
                    candidate.state_candidate_id
                ),
                component_references=("component-a",),
                integrity_requirements=("hash",),
            )
        )

        self.engine.complete_reconstruction(
            "regen-1",
            reconstruction.reconstruction_id,
            successful=True,
        )

        recovery = (
            self.engine.create_recovery_plan(
                "regen-1",
                "endpoint-1",
                reconstruction_id=(
                    reconstruction.reconstruction_id
                ),
                recovery_steps=(
                    "restore-state",
                    "validate-config",
                ),
                required_verifications=(
                    "state-integrity",
                ),
            )
        )

        self.assertEqual(
            recovery.status,
            RecoveryStatus.PLANNED,
        )

        completed = (
            self.engine.complete_recovery(
                "regen-1",
                recovery.recovery_id,
                successful=True,
            )
        )

        self.assertEqual(
            completed.status,
            RecoveryStatus.COMPLETED,
        )

    # ========================================================================
    # Integrity verification
    # ========================================================================

    def test_integrity_verification(self):

        check = IntegrityCheck(
            check_id="integrity-1",
            scope_id="scope-a",
            asset_id="endpoint-1",
            check_type="STATE_HASH",
            expected_reference="hash-a",
            observed_reference="hash-a",
            checked_at=utc_now(),
            result=IntegrityStatus.PASSED,
            confidence=0.95,
            reason="matching state hash",
        )

        self.engine.add_integrity_check(
            "regen-1",
            check,
        )

        result = self.engine.evaluate_integrity(
            "regen-1"
        )

        self.assertEqual(
            result,
            IntegrityStatus.PASSED,
        )

        self.assertEqual(
            self.regeneration.status,
            RegenerationStatus.INTEGRITY_VERIFIED,
        )

    # ========================================================================
    # Reintroduction blocked without integrity
    # ========================================================================

    def test_reintroduction_blocked_without_integrity(self):

        record = self.engine.prepare_reintroduction(
            "regen-1",
            "endpoint-1",
            approval_reference="approval-1",
        )

        self.assertEqual(
            record.status,
            ReintroductionStatus.BLOCKED,
        )

    # ========================================================================
    # Reintroduction requires approval
    # ========================================================================

    def test_reintroduction_requires_approval(self):

        check = IntegrityCheck(
            check_id="integrity-approval",
            scope_id="scope-a",
            asset_id="endpoint-1",
            check_type="STATE_HASH",
            expected_reference="hash",
            observed_reference="hash",
            checked_at=utc_now(),
            result=IntegrityStatus.PASSED,
            confidence=0.95,
        )

        self.engine.add_integrity_check(
            "regen-1",
            check,
        )

        self.engine.evaluate_integrity(
            "regen-1"
        )

        record = self.engine.prepare_reintroduction(
            "regen-1",
            "endpoint-1",
        )

        self.assertEqual(
            record.status,
            ReintroductionStatus.NOT_READY,
        )

    # ========================================================================
    # Successful controlled reintroduction
    # ========================================================================

    def test_successful_reintroduction(self):

        check = IntegrityCheck(
            check_id="integrity-final",
            scope_id="scope-a",
            asset_id="endpoint-1",
            check_type="STATE_HASH",
            expected_reference="hash",
            observed_reference="hash",
            checked_at=utc_now(),
            result=IntegrityStatus.PASSED,
            confidence=0.95,
        )

        self.engine.add_integrity_check(
            "regen-1",
            check,
        )

        self.engine.evaluate_integrity(
            "regen-1"
        )

        record = self.engine.prepare_reintroduction(
            "regen-1",
            "endpoint-1",
            approval_reference="approved-by-policy",
        )

        self.assertEqual(
            record.status,
            ReintroductionStatus.READY,
        )

        completed = (
            self.engine.complete_reintroduction(
                "regen-1",
                record.reintroduction_id,
                successful=True,
            )
        )

        self.assertEqual(
            completed.status,
            ReintroductionStatus.COMPLETED,
        )

        self.assertEqual(
            self.regeneration.status,
            RegenerationStatus.COMPLETED,
        )

    # ========================================================================
    # Scope isolation
    # ========================================================================

    def test_scope_isolation(self):

        foreign_asset = CompromisedAsset(
            asset_id="foreign",
            scope_id="scope-b",
            asset_type="endpoint",
            compromise_reference="incident-b",
            detected_at=utc_now(),
        )

        self.engine.add_asset(
            foreign_asset
        )

        with self.assertRaises(ValueError):

            self.engine.create_regeneration(
                regeneration_id="foreign-regeneration",
                scope_id="scope-a",
                asset_ids=("foreign",),
            )

    # ========================================================================
    # Global validation
    # ========================================================================

    def test_validation(self):

        self.engine.isolate_asset(
            "regen-1",
            "endpoint-1",
            isolation_reference="iso",
            confirmed=True,
            reason="test",
        )

        self.assertEqual(
            self.engine.validate(),
            [],
        )


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_phase17_tests() -> None:

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        Phase17Tests
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    if not result.wasSuccessful():
        raise AssertionError(
            "Phase 17 tests failed"
        )


if __name__ == "__main__":
    run_phase17_tests()
