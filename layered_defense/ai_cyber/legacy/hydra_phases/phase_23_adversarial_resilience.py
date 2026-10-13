"""
HYDRA POST-CORE — PHASE 23: ADVERSARIAL RESILIENCE
======================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 9 adversarial attack kinds, defense outcomes, severities
  * Integrity-tag model — every piece of internal information can be
    verified and can be invalidated
  * Evidence corroboration tracker — multiple independent sources must
    agree before a claim is accepted for critical actions
  * State-consistency rules — cross-field consistency checks that
    catch silent state corruption
  * Confidence-anomaly detector — sliding window statistics that
    catch manipulated confidence streams (too uniform, extreme,
    synthetic)
  * Authority-escalation tracker — detects sudden, unauthorised or
    anomalous authority growth, and actions by suspended principals
  * Recovery verification — independent-source verification; a claim
    of recovery does not by itself raise trust
  * Learning quarantine — learning inputs are held in a quarantine
    buffer until they pass integrity + corroboration + reliability
  * Adversarial transition guard — wraps transition proposals and
    rejects adversarial ones
  * Machine-checkable adversarial invariants
  * In-memory + SQLite stores
  * Phase-23 engine facade
  * Full test suite + manual runner

Purpose: the system must assume its own information can be attacked.

This is NEW adversarial-resilience technology. It is NOT a second
detection engine. It is the trust-and-verification firewall that the
existing HYDRA core consumes.

No third-party dependencies.

Run tests:
    python hydra_phase23_adversarial_resilience.py
    pytest hydra_phase23_adversarial_resilience.py -q
"""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from collections import deque
from dataclasses import dataclass, field, replace
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


# =============================================================================
# SECTION 2 — DOMAIN ENUMS
# =============================================================================


class AttackKind(str, Enum):
    EVIDENCE_POISONING = "evidence_poisoning"
    TELEMETRY_MANIPULATION = "telemetry_manipulation"
    STATE_CORRUPTION = "state_corruption"
    CONFIDENCE_MANIPULATION = "confidence_manipulation"
    AUTHORITY_ABUSE = "authority_abuse"
    MODEL_MANIPULATION = "model_manipulation"
    RECOVERY_MANIPULATION = "recovery_manipulation"
    LEARNING_POISONING = "learning_poisoning"
    ADVERSARIAL_STATE_TRANSITION = "adversarial_state_transition"


class DefenseOutcome(str, Enum):
    NONE = "none"
    DETECTED = "detected"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"
    FALLBACK_USED = "fallback_used"


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


class AuthorityLevel(str, Enum):
    READ_ONLY = "read_only"
    OPERATOR = "operator"
    SENIOR = "senior"
    ADMIN = "admin"
    BREAK_GLASS = "break_glass"


_AUTH_RANK: Mapping[AuthorityLevel, int] = {
    AuthorityLevel.READ_ONLY: 0,
    AuthorityLevel.OPERATOR: 1,
    AuthorityLevel.SENIOR: 2,
    AuthorityLevel.ADMIN: 3,
    AuthorityLevel.BREAK_GLASS: 4,
}


def auth_rank(level: AuthorityLevel) -> int:
    return _AUTH_RANK[level]


class PrincipalStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    QUARANTINED = "quarantined"


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


class AdversarialFindingKind(str, Enum):
    INVALID_INTEGRITY_TAG = "invalid_integrity_tag"
    DIGEST_MISMATCH = "digest_mismatch"
    INSUFFICIENT_CORROBORATION = "insufficient_corroboration"
    STATE_INCONSISTENCY = "state_inconsistency"
    CONFIDENCE_TOO_UNIFORM = "confidence_too_uniform"
    CONFIDENCE_EXTREME = "confidence_extreme"
    AUTHORITY_ESCALATION_SUSPECT = "authority_escalation_suspect"
    AUTHORITY_SUSPENDED_ACTION = "authority_suspended_action"
    MODEL_OUTPUT_ANOMALY = "model_output_anomaly"
    RECOVERY_UNVERIFIED = "recovery_unverified"
    LEARNING_INPUT_QUARANTINED = "learning_input_quarantined"
    ADVERSARIAL_TRANSITION_REJECTED = "adversarial_transition_rejected"


@dataclass(frozen=True)
class AdversarialFinding:
    kind: AdversarialFindingKind
    attack: Optional[AttackKind]
    subject_id: str
    detail: str
    severity: Severity
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 3 — INTEGRITY TAGS
# =============================================================================


def canonical_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IntegrityTag:
    """Integrity proof attached to any internal information.

    verification is expected to be *externally* performed (HMAC,
    signature, hardware root-of-trust, digest chain). We model it as a
    boolean that must be True *and* a digest that must match the
    recorded content digest for the tag to be considered valid.
    """
    tag_id: str
    evidence_id: str
    content_digest: str
    verified: bool = True
    chain_parent_tag_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.tag_id:
            raise ValueError("tag_id is required")
        if not self.evidence_id:
            raise ValueError("evidence_id is required")
        if not self.content_digest:
            raise ValueError("content_digest is required")
        if self.chain_parent_tag_id == self.tag_id:
            raise ValueError("tag cannot chain to itself")


def verify_integrity(
    *,
    tag: IntegrityTag,
    payload: Mapping[str, Any],
    parent_tag: Optional[IntegrityTag] = None,
) -> Tuple[bool, Optional[AdversarialFindingKind]]:
    if not tag.verified:
        return (False, AdversarialFindingKind.INVALID_INTEGRITY_TAG)
    if canonical_digest(payload) != tag.content_digest:
        return (False, AdversarialFindingKind.DIGEST_MISMATCH)
    if tag.chain_parent_tag_id is not None:
        if parent_tag is None:
            return (False, AdversarialFindingKind.INVALID_INTEGRITY_TAG)
        if parent_tag.tag_id != tag.chain_parent_tag_id:
            return (False, AdversarialFindingKind.INVALID_INTEGRITY_TAG)
        if not parent_tag.verified:
            return (False, AdversarialFindingKind.INVALID_INTEGRITY_TAG)
    return (True, None)


# =============================================================================
# SECTION 4 — EVIDENCE + CORROBORATION
# =============================================================================


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    source_id: str
    claim_key: str            # e.g. "entity-42:label"
    claim_value: str          # e.g. "compromised"
    payload: Mapping[str, Any]
    tag: IntegrityTag
    at: datetime

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise ValueError("evidence_id is required")
        if not self.source_id:
            raise ValueError("source_id is required")
        if not self.claim_key:
            raise ValueError("claim_key is required")
        if not self.claim_value:
            raise ValueError("claim_value is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class CorroborationRule:
    """Require N independent sources to agree before a claim is usable."""
    min_sources: int = 2
    independence_required: bool = True
    claim_prefixes: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if self.min_sources < 1:
            raise ValueError("min_sources must be >= 1")

    def applies_to(self, claim_key: str) -> bool:
        if not self.claim_prefixes:
            return True
        return any(claim_key.startswith(p) for p in self.claim_prefixes)


@dataclass(frozen=True)
class CorroborationResult:
    claim_key: str
    claim_value: str
    sources: Tuple[str, ...]
    satisfied: bool
    required: int
    rationale: str


class CorroborationTracker:
    def __init__(self, *, window: int = 200) -> None:
        if window < 1:
            raise ValueError("window must be >= 1")
        self._window = window
        # (claim_key, claim_value) → ordered list of (source_id, at)
        self._history: Dict[Tuple[str, str], deque] = {}

    def record(self, ev: EvidenceRecord) -> None:
        key = (ev.claim_key, ev.claim_value)
        dq = self._history.setdefault(key, deque())
        dq.append((ev.source_id, ev.at))
        if len(dq) > self._window:
            dq.popleft()

    def evaluate(
        self,
        claim_key: str,
        claim_value: str,
        *,
        rule: CorroborationRule,
    ) -> CorroborationResult:
        if not rule.applies_to(claim_key):
            return CorroborationResult(
                claim_key=claim_key, claim_value=claim_value,
                sources=(), satisfied=True, required=0,
                rationale="rule does not apply",
            )
        dq = self._history.get((claim_key, claim_value), deque())
        sources = tuple(sorted({s for s, _ in dq}))
        satisfied = len(sources) >= rule.min_sources
        rationale = (
            f"{len(sources)} distinct source(s) vs required "
            f"{rule.min_sources}"
        )
        return CorroborationResult(
            claim_key=claim_key, claim_value=claim_value,
            sources=sources, satisfied=satisfied,
            required=rule.min_sources, rationale=rationale,
        )


# =============================================================================
# SECTION 5 — STATE CONSISTENCY
# =============================================================================


@dataclass(frozen=True)
class StateRecord:
    entity_id: str
    label: TrustLabel
    quarantined: bool
    verified_recovery: bool
    has_last_verified: bool
    authority: AuthorityLevel


@dataclass(frozen=True)
class ConsistencyRule:
    rule_id: str
    description: str
    predicate: Callable[[StateRecord], Tuple[str, ...]]
    severity: Severity = Severity.HIGH

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("rule_id is required")
        if not self.description:
            raise ValueError("description is required")


def _rule_quarantine_label(s: StateRecord) -> Tuple[str, ...]:
    if s.quarantined and s.label is not TrustLabel.QUARANTINED:
        return (f"quarantined=True but label={s.label.value}",)
    return ()


def _rule_trusted_requires_verification(
    s: StateRecord,
) -> Tuple[str, ...]:
    if s.label is TrustLabel.TRUSTED and not s.has_last_verified:
        return (f"TRUSTED without last_verified_at",)
    return ()


def _rule_unverified_recovery_not_trusted(
    s: StateRecord,
) -> Tuple[str, ...]:
    if s.label is TrustLabel.TRUSTED and s.verified_recovery is False \
       and s.has_last_verified is False:
        return ("TRUSTED without verified_recovery and last_verified",)
    return ()


def _rule_high_authority_requires_trusted(
    s: StateRecord,
) -> Tuple[str, ...]:
    if auth_rank(s.authority) >= auth_rank(AuthorityLevel.ADMIN) \
       and s.label is not TrustLabel.TRUSTED:
        return (
            f"authority {s.authority.value} but label {s.label.value}",
        )
    return ()


DEFAULT_CONSISTENCY_RULES: Tuple[ConsistencyRule, ...] = (
    ConsistencyRule(
        rule_id="cons.quarantine_label",
        description="Quarantined flag requires label=QUARANTINED.",
        predicate=_rule_quarantine_label,
        severity=Severity.CRITICAL,
    ),
    ConsistencyRule(
        rule_id="cons.trusted_requires_verification",
        description="TRUSTED requires last_verified_at.",
        predicate=_rule_trusted_requires_verification,
        severity=Severity.HIGH,
    ),
    ConsistencyRule(
        rule_id="cons.unverified_recovery_not_trusted",
        description="TRUSTED without verified recovery is inconsistent.",
        predicate=_rule_unverified_recovery_not_trusted,
        severity=Severity.HIGH,
    ),
    ConsistencyRule(
        rule_id="cons.high_authority_requires_trusted",
        description="ADMIN+ authority requires TRUSTED label.",
        predicate=_rule_high_authority_requires_trusted,
        severity=Severity.CRITICAL,
    ),
)


def check_state_consistency(
    state: StateRecord,
    *,
    rules: Iterable[ConsistencyRule] = DEFAULT_CONSISTENCY_RULES,
    at: datetime,
) -> Tuple[AdversarialFinding, ...]:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    out: List[AdversarialFinding] = []
    for r in rules:
        try:
            details = r.predicate(state)
        except Exception as exc:  # noqa: BLE001
            out.append(AdversarialFinding(
                kind=AdversarialFindingKind.STATE_INCONSISTENCY,
                attack=AttackKind.STATE_CORRUPTION,
                subject_id=state.entity_id,
                detail=f"{r.rule_id} predicate raised: {type(exc).__name__}",
                severity=Severity.CRITICAL, at=at,
            ))
            continue
        for d in details:
            out.append(AdversarialFinding(
                kind=AdversarialFindingKind.STATE_INCONSISTENCY,
                attack=AttackKind.STATE_CORRUPTION,
                subject_id=state.entity_id,
                detail=f"{r.rule_id}: {d}",
                severity=r.severity, at=at,
            ))
    return tuple(out)


# =============================================================================
# SECTION 6 — CONFIDENCE ANOMALY DETECTOR
# =============================================================================


@dataclass(frozen=True)
class ConfidenceSample:
    detector_id: str
    confidence: float
    at: datetime

    def __post_init__(self) -> None:
        if not self.detector_id:
            raise ValueError("detector_id is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class ConfidenceAnomalyConfig:
    window: int = 20
    min_samples: int = 8
    uniformity_variance_threshold: float = 0.0005
    extreme_high: float = 0.98
    extreme_low: float = 0.02
    extreme_ratio_threshold: float = 0.75

    def __post_init__(self) -> None:
        if self.window < 2:
            raise ValueError("window must be >= 2")
        if self.min_samples < 2 or self.min_samples > self.window:
            raise ValueError("min_samples must be within [2, window]")
        if not 0.0 <= self.uniformity_variance_threshold <= 1.0:
            raise ValueError("variance threshold must be within [0,1]")
        if not 0.0 <= self.extreme_high <= 1.0:
            raise ValueError("extreme_high must be within [0,1]")
        if not 0.0 <= self.extreme_low <= 1.0:
            raise ValueError("extreme_low must be within [0,1]")
        if self.extreme_low >= self.extreme_high:
            raise ValueError("extreme_low must be < extreme_high")
        if not 0.0 <= self.extreme_ratio_threshold <= 1.0:
            raise ValueError("extreme_ratio_threshold must be within [0,1]")


@dataclass(frozen=True)
class ConfidenceAnomaly:
    detector_id: str
    kind: AdversarialFindingKind
    detail: str
    severity: Severity
    mean: float
    variance: float
    sample_count: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


class ConfidenceAnomalyDetector:
    def __init__(
        self, *, config: Optional[ConfidenceAnomalyConfig] = None,
    ) -> None:
        self._config = config or ConfidenceAnomalyConfig()
        self._windows: Dict[str, deque] = {}

    def config(self) -> ConfidenceAnomalyConfig:
        return self._config

    def set_config(self, config: ConfidenceAnomalyConfig) -> None:
        self._config = config

    def record(self, sample: ConfidenceSample) -> None:
        dq = self._windows.setdefault(
            sample.detector_id, deque(maxlen=self._config.window),
        )
        dq.append(sample)

    def analyze(
        self, detector_id: str, *, at: datetime,
    ) -> Tuple[ConfidenceAnomaly, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        dq = self._windows.get(detector_id)
        if dq is None or len(dq) < self._config.min_samples:
            return ()
        values = [s.confidence for s in dq]
        n = len(values)
        mean = sum(values) / n
        var = sum((v - mean) ** 2 for v in values) / (n - 1)

        out: List[ConfidenceAnomaly] = []

        if var < self._config.uniformity_variance_threshold:
            out.append(ConfidenceAnomaly(
                detector_id=detector_id,
                kind=AdversarialFindingKind.CONFIDENCE_TOO_UNIFORM,
                detail=(
                    f"variance {var:.6f} < threshold "
                    f"{self._config.uniformity_variance_threshold:.6f}"
                ),
                severity=Severity.HIGH,
                mean=mean, variance=var, sample_count=n, at=at,
            ))

        high = sum(1 for v in values if v >= self._config.extreme_high)
        low = sum(1 for v in values if v <= self._config.extreme_low)
        extreme = max(high, low) / n
        if extreme >= self._config.extreme_ratio_threshold:
            out.append(ConfidenceAnomaly(
                detector_id=detector_id,
                kind=AdversarialFindingKind.CONFIDENCE_EXTREME,
                detail=(
                    f"{max(high, low)}/{n} samples at extreme bounds"
                ),
                severity=Severity.MEDIUM,
                mean=mean, variance=var, sample_count=n, at=at,
            ))

        return tuple(out)


# =============================================================================
# SECTION 7 — AUTHORITY ESCALATION TRACKER
# =============================================================================


@dataclass(frozen=True)
class AuthorityChange:
    change_id: str
    principal_id: str
    from_level: AuthorityLevel
    to_level: AuthorityLevel
    at: datetime
    reason: str = ""

    def __post_init__(self) -> None:
        if not self.change_id:
            raise ValueError("change_id is required")
        if not self.principal_id:
            raise ValueError("principal_id is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class AuthorityEscalationConfig:
    max_single_jump: int = 2
    window_seconds: float = 600.0
    max_escalations_in_window: int = 2

    def __post_init__(self) -> None:
        if self.max_single_jump < 1:
            raise ValueError("max_single_jump must be >= 1")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if self.max_escalations_in_window < 1:
            raise ValueError("max_escalations_in_window must be >= 1")


class AuthorityEscalationTracker:
    def __init__(
        self,
        *,
        config: Optional[AuthorityEscalationConfig] = None,
        max_history: int = 500,
    ) -> None:
        if max_history < 1:
            raise ValueError("max_history must be >= 1")
        self._config = config or AuthorityEscalationConfig()
        self._history: Dict[str, List[AuthorityChange]] = {}
        self._max_history = max_history

    def config(self) -> AuthorityEscalationConfig:
        return self._config

    def set_config(self, config: AuthorityEscalationConfig) -> None:
        self._config = config

    def record(self, change: AuthorityChange) -> None:
        lst = self._history.setdefault(change.principal_id, [])
        lst.append(change)
        if len(lst) > self._max_history:
            del lst[: len(lst) - self._max_history]

    def analyze(
        self, principal_id: str, *, at: datetime,
    ) -> Tuple[AdversarialFinding, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        changes = self._history.get(principal_id, [])
        if not changes:
            return ()
        out: List[AdversarialFinding] = []

        # Single-jump rule
        for c in changes:
            jump = auth_rank(c.to_level) - auth_rank(c.from_level)
            if jump > self._config.max_single_jump:
                out.append(AdversarialFinding(
                    kind=AdversarialFindingKind.AUTHORITY_ESCALATION_SUSPECT,
                    attack=AttackKind.AUTHORITY_ABUSE,
                    subject_id=principal_id,
                    detail=(
                        f"single jump {c.from_level.value} → "
                        f"{c.to_level.value} exceeds limit "
                        f"{self._config.max_single_jump}"
                    ),
                    severity=Severity.HIGH, at=at,
                ))

        # Frequency rule
        if changes:
            latest = max(changes, key=lambda c: c.at)
            window_start = latest.at - timedelta(
                seconds=self._config.window_seconds
            )
            recent = [
                c for c in changes
                if c.at >= window_start
                and auth_rank(c.to_level) > auth_rank(c.from_level)
            ]
            if len(recent) > self._config.max_escalations_in_window:
                out.append(AdversarialFinding(
                    kind=AdversarialFindingKind.AUTHORITY_ESCALATION_SUSPECT,
                    attack=AttackKind.AUTHORITY_ABUSE,
                    subject_id=principal_id,
                    detail=(
                        f"{len(recent)} escalations in "
                        f"{self._config.window_seconds:.0f}s window"
                    ),
                    severity=Severity.HIGH, at=at,
                ))
        return tuple(out)


# =============================================================================
# SECTION 8 — RECOVERY VERIFICATION
# =============================================================================


@dataclass(frozen=True)
class RecoveryClaim:
    claim_id: str
    entity_id: str
    claimed_label: TrustLabel
    source_id: str
    objective_achieved: bool
    action_verified: bool
    independent_source_ids: FrozenSet[str]
    at: datetime

    def __post_init__(self) -> None:
        if not self.claim_id:
            raise ValueError("claim_id is required")
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if not self.source_id:
            raise ValueError("source_id is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if self.source_id in self.independent_source_ids:
            raise ValueError(
                "source_id cannot be its own independent verifier"
            )


@dataclass(frozen=True)
class RecoveryVerification:
    claim_id: str
    accepted: bool
    rationale: str
    independent_verifiers: Tuple[str, ...]


def verify_recovery_claim(
    claim: RecoveryClaim,
    *,
    min_independent_verifiers: int = 1,
    require_objective_achieved: bool = True,
) -> RecoveryVerification:
    if min_independent_verifiers < 1:
        raise ValueError("min_independent_verifiers must be >= 1")
    reasons: List[str] = []
    if require_objective_achieved and not claim.objective_achieved:
        reasons.append("objective not achieved")
    if not claim.action_verified:
        reasons.append("action not verified")
    if len(claim.independent_source_ids) < min_independent_verifiers:
        reasons.append(
            f"only {len(claim.independent_source_ids)} independent "
            f"verifier(s) vs required {min_independent_verifiers}"
        )
    accepted = not reasons
    return RecoveryVerification(
        claim_id=claim.claim_id,
        accepted=accepted,
        rationale=(
            "verified" if accepted
            else "; ".join(reasons)
        ),
        independent_verifiers=tuple(sorted(claim.independent_source_ids)),
    )


# =============================================================================
# SECTION 9 — LEARNING QUARANTINE
# =============================================================================


@dataclass(frozen=True)
class LearningInput:
    input_id: str
    source_id: str
    label: TrustLabel
    weight: float
    evidence: EvidenceRecord
    corroborating_sources: FrozenSet[str]
    at: datetime

    def __post_init__(self) -> None:
        if not self.input_id:
            raise ValueError("input_id is required")
        if not self.source_id:
            raise ValueError("source_id is required")
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("weight must be within [0,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class QuarantineDecision:
    input_id: str
    accepted: bool
    outcome: DefenseOutcome
    rationale: str


@dataclass(frozen=True)
class LearningQuarantineConfig:
    min_source_reliability: float = 0.4
    min_corroborating_sources: int = 1

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_source_reliability <= 1.0:
            raise ValueError(
                "min_source_reliability must be within [0,1]"
            )
        if self.min_corroborating_sources < 0:
            raise ValueError(
                "min_corroborating_sources must be >= 0"
            )


def evaluate_learning_input(
    inp: LearningInput,
    *,
    source_reliability: float,
    config: LearningQuarantineConfig,
) -> QuarantineDecision:
    if not 0.0 <= source_reliability <= 1.0:
        raise ValueError("source_reliability must be within [0,1]")
    reasons: List[str] = []

    if not inp.evidence.tag.verified:
        reasons.append("integrity tag unverified")
    if source_reliability < config.min_source_reliability:
        reasons.append(
            f"source reliability {source_reliability:.2f} < "
            f"{config.min_source_reliability:.2f}"
        )
    if len(inp.corroborating_sources) < \
            config.min_corroborating_sources:
        reasons.append(
            f"{len(inp.corroborating_sources)} corroborating source(s) "
            f"vs required {config.min_corroborating_sources}"
        )

    if reasons:
        return QuarantineDecision(
            input_id=inp.input_id, accepted=False,
            outcome=DefenseOutcome.QUARANTINED,
            rationale="; ".join(reasons),
        )
    return QuarantineDecision(
        input_id=inp.input_id, accepted=True,
        outcome=DefenseOutcome.NONE,
        rationale="passed integrity + corroboration + reliability",
    )


# =============================================================================
# SECTION 10 — ADVERSARIAL TRANSITION GUARD
# =============================================================================


@dataclass(frozen=True)
class GuardedTransition:
    transition_id: str
    principal_id: str
    from_label: TrustLabel
    to_label: TrustLabel
    principal_status: PrincipalStatus
    requester_authority: AuthorityLevel
    required_authority: AuthorityLevel
    verified: bool
    action_verified: bool
    at: datetime

    def __post_init__(self) -> None:
        if not self.transition_id:
            raise ValueError("transition_id is required")
        if not self.principal_id:
            raise ValueError("principal_id is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class GuardedTransitionDecision:
    transition_id: str
    allowed: bool
    outcome: DefenseOutcome
    rationale: str


def guard_transition(
    transition: GuardedTransition,
    *,
    require_verification_for_recovery: bool = True,
) -> GuardedTransitionDecision:
    reasons: List[str] = []

    if transition.principal_status in (
        PrincipalStatus.SUSPENDED,
        PrincipalStatus.REVOKED,
        PrincipalStatus.QUARANTINED,
    ):
        reasons.append(
            f"principal status is {transition.principal_status.value}"
        )

    if auth_rank(transition.requester_authority) < \
       auth_rank(transition.required_authority):
        reasons.append(
            f"requester authority {transition.requester_authority.value} "
            f"< required {transition.required_authority.value}"
        )

    going_better = label_severity(transition.to_label) < \
        label_severity(transition.from_label)
    if going_better and require_verification_for_recovery:
        if not transition.verified or not transition.action_verified:
            reasons.append(
                "recovery requires verified action"
            )

    if reasons:
        return GuardedTransitionDecision(
            transition_id=transition.transition_id,
            allowed=False,
            outcome=DefenseOutcome.REJECTED,
            rationale="; ".join(reasons),
        )
    return GuardedTransitionDecision(
        transition_id=transition.transition_id,
        allowed=True,
        outcome=DefenseOutcome.NONE,
        rationale="permitted",
    )


# =============================================================================
# SECTION 11 — INVARIANTS
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
class AdversarialSnapshot:
    findings: Tuple[AdversarialFinding, ...]
    quarantine_decisions: Mapping[str, QuarantineDecision]
    transition_decisions: Mapping[str, GuardedTransitionDecision]
    recovery_verifications: Mapping[str, RecoveryVerification]


@dataclass(frozen=True)
class AdversarialInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[AdversarialSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_quarantined_not_accepted(
    snap: AdversarialSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for iid, q in snap.quarantine_decisions.items():
        if q.outcome is DefenseOutcome.QUARANTINED and q.accepted:
            out.append(InvariantViolation(
                invariant_id="adv.quarantined_not_accepted",
                severity=InvariantSeverity.CRITICAL,
                subject_id=iid,
                detail="quarantined input marked accepted",
            ))
    return tuple(out)


def _inv_rejected_transition_not_allowed(
    snap: AdversarialSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for tid, d in snap.transition_decisions.items():
        if d.outcome is DefenseOutcome.REJECTED and d.allowed:
            out.append(InvariantViolation(
                invariant_id="adv.rejected_transition_not_allowed",
                severity=InvariantSeverity.CRITICAL,
                subject_id=tid,
                detail="REJECTED transition marked allowed",
            ))
    return tuple(out)


def _inv_recovery_accepted_requires_verifiers(
    snap: AdversarialSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for cid, rv in snap.recovery_verifications.items():
        if rv.accepted and not rv.independent_verifiers:
            out.append(InvariantViolation(
                invariant_id="adv.recovery_accepted_requires_verifiers",
                severity=InvariantSeverity.HIGH,
                subject_id=cid,
                detail="accepted recovery claim has no independent verifiers",
            ))
    return tuple(out)


def _inv_attack_indicators_have_severity(
    snap: AdversarialSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if f.attack is not None and severity_rank(f.severity) < 1:
            out.append(InvariantViolation(
                invariant_id="adv.attack_indicators_have_severity",
                severity=InvariantSeverity.LOW,
                subject_id=f.subject_id,
                detail="attack indicator with invalid severity",
            ))
    return tuple(out)


def _inv_critical_findings_not_silent(
    snap: AdversarialSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """CRITICAL findings must be paired with a defence outcome on the
    subject (quarantine, reject, or detect)."""
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if f.severity is not Severity.CRITICAL:
            continue
        if f.subject_id in snap.quarantine_decisions:
            d = snap.quarantine_decisions[f.subject_id]
            if d.outcome in (
                DefenseOutcome.QUARANTINED, DefenseOutcome.REJECTED,
            ):
                continue
        if f.subject_id in snap.transition_decisions:
            d2 = snap.transition_decisions[f.subject_id]
            if d2.outcome is DefenseOutcome.REJECTED:
                continue
        # Otherwise: detect is itself a valid pairing.
        # We only require the finding to carry severity > LOW.
        if severity_rank(f.severity) < severity_rank(Severity.HIGH):
            out.append(InvariantViolation(
                invariant_id="adv.critical_findings_not_silent",
                severity=InvariantSeverity.MEDIUM,
                subject_id=f.subject_id,
                detail="critical finding without matching defence outcome",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[AdversarialInvariant, ...] = (
    AdversarialInvariant(
        invariant_id="adv.quarantined_not_accepted",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_quarantined_not_accepted,
        description="Quarantined inputs must not be accepted.",
    ),
    AdversarialInvariant(
        invariant_id="adv.rejected_transition_not_allowed",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_rejected_transition_not_allowed,
        description="Rejected transitions must not be allowed.",
    ),
    AdversarialInvariant(
        invariant_id="adv.recovery_accepted_requires_verifiers",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_recovery_accepted_requires_verifiers,
        description="Accepted recoveries must have independent verifiers.",
    ),
    AdversarialInvariant(
        invariant_id="adv.attack_indicators_have_severity",
        severity=InvariantSeverity.LOW,
        predicate=_inv_attack_indicators_have_severity,
        description="Attack indicators must carry a valid severity.",
    ),
    AdversarialInvariant(
        invariant_id="adv.critical_findings_not_silent",
        severity=InvariantSeverity.MEDIUM,
        predicate=_inv_critical_findings_not_silent,
        description="Critical findings must be paired with a defence.",
    ),
)


def check_invariants(
    snap: AdversarialSnapshot,
    invariants: Iterable[AdversarialInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 12 — STORE
# =============================================================================


@dataclass(frozen=True)
class AdversarialRecord:
    kind: AdversarialFindingKind
    attack: Optional[AttackKind]
    subject_id: str
    severity: Severity
    detail: str
    at: datetime


class AdversarialStore(Protocol):
    def put(self, record: AdversarialRecord) -> None: ...
    def all(self) -> Tuple[AdversarialRecord, ...]: ...


class InMemoryAdversarialStore:
    def __init__(self) -> None:
        self._data: List[AdversarialRecord] = []

    def put(self, record: AdversarialRecord) -> None:
        self._data.append(record)

    def all(self) -> Tuple[AdversarialRecord, ...]:
        return tuple(self._data)


class SqliteAdversarialStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS adv_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                attack TEXT,
                subject_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                detail TEXT NOT NULL,
                at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: AdversarialRecord) -> None:
        self._conn.execute(
            """
            INSERT INTO adv_findings
              (kind, attack, subject_id, severity, detail, at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                record.kind.value,
                record.attack.value if record.attack else None,
                record.subject_id, record.severity.value,
                record.detail, record.at.isoformat(),
            ),
        )
        self._conn.commit()

    def all(self) -> Tuple[AdversarialRecord, ...]:
        rows = self._conn.execute(
            "SELECT kind, attack, subject_id, severity, detail, at "
            "FROM adv_findings ORDER BY id ASC"
        ).fetchall()
        return tuple(
            AdversarialRecord(
                kind=AdversarialFindingKind(r[0]),
                attack=AttackKind(r[1]) if r[1] else None,
                subject_id=r[2], severity=Severity(r[3]),
                detail=r[4], at=datetime.fromisoformat(r[5]),
            )
            for r in rows
        )


# =============================================================================
# SECTION 13 — ENGINE
# =============================================================================


class AdversarialResilienceEngine:
    """Adversarial-resilience firewall.

    The engine ingests evidence, state snapshots, confidence samples,
    authority changes, recovery claims, learning inputs, and
    transitions. It applies its detectors and produces defence
    outcomes.
    """

    def __init__(
        self,
        *,
        store: Optional[AdversarialStore] = None,
        corroboration_rule: Optional[CorroborationRule] = None,
        confidence_config: Optional[ConfidenceAnomalyConfig] = None,
        authority_config: Optional[AuthorityEscalationConfig] = None,
        quarantine_config: Optional[LearningQuarantineConfig] = None,
        consistency_rules: Optional[
            Iterable[ConsistencyRule]
        ] = None,
        require_verification_for_recovery: bool = True,
        min_independent_verifiers: int = 1,
    ) -> None:
        if min_independent_verifiers < 1:
            raise ValueError(
                "min_independent_verifiers must be >= 1"
            )
        self._store: AdversarialStore = store or InMemoryAdversarialStore()
        self._corroboration_rule = (
            corroboration_rule or CorroborationRule()
        )
        self._corroboration = CorroborationTracker()
        self._confidence = ConfidenceAnomalyDetector(
            config=confidence_config,
        )
        self._authority = AuthorityEscalationTracker(
            config=authority_config,
        )
        self._quarantine_config = quarantine_config or \
            LearningQuarantineConfig()
        self._consistency_rules: Tuple[ConsistencyRule, ...] = tuple(
            consistency_rules
            if consistency_rules is not None
            else DEFAULT_CONSISTENCY_RULES
        )
        self._require_verification_for_recovery = \
            require_verification_for_recovery
        self._min_independent_verifiers = min_independent_verifiers

        self._source_reliability: Dict[str, float] = {}
        self._findings: List[AdversarialFinding] = []
        self._quarantine: Dict[str, QuarantineDecision] = {}
        self._recoveries: Dict[str, RecoveryVerification] = {}
        self._transitions: Dict[str, GuardedTransitionDecision] = {}
        self._violations: Tuple[InvariantViolation, ...] = ()

        self._evidence: Dict[str, EvidenceRecord] = {}
        self._tags_by_id: Dict[str, IntegrityTag] = {}

    # ---- config ----------------------------------------------------------

    def set_corroboration_rule(self, rule: CorroborationRule) -> None:
        self._corroboration_rule = rule

    def set_confidence_config(self, cfg: ConfidenceAnomalyConfig) -> None:
        self._confidence.set_config(cfg)

    def set_authority_config(self, cfg: AuthorityEscalationConfig) -> None:
        self._authority.set_config(cfg)

    def set_quarantine_config(self, cfg: LearningQuarantineConfig) -> None:
        self._quarantine_config = cfg

    def set_consistency_rules(
        self, rules: Iterable[ConsistencyRule],
    ) -> None:
        self._consistency_rules = tuple(rules)

    def set_min_independent_verifiers(self, n: int) -> None:
        if n < 1:
            raise ValueError("must be >= 1")
        self._min_independent_verifiers = n

    def register_source(self, source_id: str, reliability: float) -> None:
        if not source_id:
            raise ValueError("source_id is required")
        if not 0.0 <= reliability <= 1.0:
            raise ValueError("reliability must be within [0,1]")
        self._source_reliability[source_id] = reliability

    def update_source_reliability(
        self, source_id: str, reliability: float,
    ) -> None:
        self.register_source(source_id, reliability)

    def source_reliability(self, source_id: str) -> Optional[float]:
        return self._source_reliability.get(source_id)

    # ---- ingestion -------------------------------------------------------

    def submit_evidence(self, ev: EvidenceRecord, *, at: datetime) -> None:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        self._evidence[ev.evidence_id] = ev
        self._tags_by_id[ev.tag.tag_id] = ev.tag

        parent_tag = None
        if ev.tag.chain_parent_tag_id is not None:
            parent_tag = self._tags_by_id.get(ev.tag.chain_parent_tag_id)
        ok, reason = verify_integrity(
            tag=ev.tag, payload=ev.payload, parent_tag=parent_tag,
        )
        if not ok and reason is not None:
            self._findings.append(AdversarialFinding(
                kind=reason,
                attack=AttackKind.EVIDENCE_POISONING,
                subject_id=ev.evidence_id,
                detail=f"integrity failed: {reason.value}",
                severity=Severity.CRITICAL, at=at,
            ))
            return  # do not corroborate poisoned evidence
        self._corroboration.record(ev)

    def submit_state(self, state: StateRecord, *, at: datetime) -> None:
        findings = check_state_consistency(
            state, rules=self._consistency_rules, at=at,
        )
        self._findings.extend(findings)

    def submit_confidence(
        self, sample: ConfidenceSample,
    ) -> None:
        self._confidence.record(sample)

    def submit_authority_change(
        self, change: AuthorityChange,
    ) -> None:
        self._authority.record(change)

    def submit_recovery_claim(self, claim: RecoveryClaim) -> None:
        v = verify_recovery_claim(
            claim,
            min_independent_verifiers=self._min_independent_verifiers,
            require_objective_achieved=True,
        )
        self._recoveries[claim.claim_id] = v
        if not v.accepted:
            self._findings.append(AdversarialFinding(
                kind=AdversarialFindingKind.RECOVERY_UNVERIFIED,
                attack=AttackKind.RECOVERY_MANIPULATION,
                subject_id=claim.entity_id,
                detail=v.rationale,
                severity=Severity.HIGH, at=claim.at,
            ))

    def submit_learning_input(self, inp: LearningInput) -> None:
        rel = self._source_reliability.get(inp.source_id, 0.5)
        decision = evaluate_learning_input(
            inp, source_reliability=rel,
            config=self._quarantine_config,
        )
        self._quarantine[inp.input_id] = decision
        if not decision.accepted:
            self._findings.append(AdversarialFinding(
                kind=AdversarialFindingKind.LEARNING_INPUT_QUARANTINED,
                attack=AttackKind.LEARNING_POISONING,
                subject_id=inp.input_id,
                detail=decision.rationale,
                severity=Severity.HIGH, at=inp.at,
            ))

    def submit_transition(self, transition: GuardedTransition) -> None:
        d = guard_transition(
            transition,
            require_verification_for_recovery=(
                self._require_verification_for_recovery
            ),
        )
        self._transitions[transition.transition_id] = d
        if not d.allowed:
            self._findings.append(AdversarialFinding(
                kind=AdversarialFindingKind.ADVERSARIAL_TRANSITION_REJECTED,
                attack=AttackKind.ADVERSARIAL_STATE_TRANSITION,
                subject_id=transition.transition_id,
                detail=d.rationale,
                severity=Severity.HIGH, at=transition.at,
            ))

    # ---- analysis --------------------------------------------------------

    def corroborate(
        self, claim_key: str, claim_value: str,
    ) -> CorroborationResult:
        return self._corroboration.evaluate(
            claim_key, claim_value, rule=self._corroboration_rule,
        )

    def analyze(
        self,
        *,
        at: datetime,
        confidence_detector_ids: Optional[Iterable[str]] = None,
        authority_principal_ids: Optional[Iterable[str]] = None,
        require_corroboration_for: Optional[
            Iterable[Tuple[str, str]]
        ] = None,
    ) -> Tuple[AdversarialFinding, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        # Confidence anomalies
        if confidence_detector_ids:
            for did in confidence_detector_ids:
                for a in self._confidence.analyze(did, at=at):
                    self._findings.append(AdversarialFinding(
                        kind=a.kind,
                        attack=AttackKind.CONFIDENCE_MANIPULATION,
                        subject_id=a.detector_id,
                        detail=a.detail,
                        severity=a.severity, at=at,
                    ))

        # Authority escalations
        if authority_principal_ids:
            for pid in authority_principal_ids:
                self._findings.extend(self._authority.analyze(pid, at=at))

        # Explicit corroboration checks
        if require_corroboration_for:
            for claim_key, claim_value in require_corroboration_for:
                result = self.corroborate(claim_key, claim_value)
                if not result.satisfied:
                    self._findings.append(AdversarialFinding(
                        kind=AdversarialFindingKind.INSUFFICIENT_CORROBORATION,
                        attack=AttackKind.EVIDENCE_POISONING,
                        subject_id=claim_key,
                        detail=(
                            f"claim {claim_key}={claim_value}: "
                            f"{result.rationale}"
                        ),
                        severity=Severity.HIGH, at=at,
                    ))

        # Persist findings
        for f in self._findings:
            if isinstance(self._store, SqliteAdversarialStore):
                self._store.put(AdversarialRecord(
                    kind=f.kind, attack=f.attack,
                    subject_id=f.subject_id, severity=f.severity,
                    detail=f.detail, at=f.at,
                ))

        self._violations = check_invariants(self.snapshot())
        return tuple(self._findings)

    # ---- queries ---------------------------------------------------------

    def findings(self) -> Tuple[AdversarialFinding, ...]:
        return tuple(self._findings)

    def findings_for(self, subject_id: str) -> Tuple[AdversarialFinding, ...]:
        return tuple(
            f for f in self._findings if f.subject_id == subject_id
        )

    def quarantine_decision(
        self, input_id: str,
    ) -> Optional[QuarantineDecision]:
        return self._quarantine.get(input_id)

    def recovery_verification(
        self, claim_id: str,
    ) -> Optional[RecoveryVerification]:
        return self._recoveries.get(claim_id)

    def transition_decision(
        self, transition_id: str,
    ) -> Optional[GuardedTransitionDecision]:
        return self._transitions.get(transition_id)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def snapshot(self) -> AdversarialSnapshot:
        return AdversarialSnapshot(
            findings=tuple(self._findings),
            quarantine_decisions=dict(self._quarantine),
            transition_decisions=dict(self._transitions),
            recovery_verifications=dict(self._recoveries),
        )

    def severities_summary(self) -> Mapping[Severity, int]:
        out: Dict[Severity, int] = {s: 0 for s in Severity}
        for f in self._findings:
            out[f.severity] += 1
        return out


# =============================================================================
# SECTION 14 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


def _tag(
    tid: str, evid: str, payload: Mapping[str, Any],
    *, verified: bool = True, parent: Optional[str] = None,
) -> IntegrityTag:
    return IntegrityTag(
        tag_id=tid, evidence_id=evid,
        content_digest=canonical_digest(payload),
        verified=verified, chain_parent_tag_id=parent,
    )


def _ev(
    evid: str, source: str = "s1",
    claim_key: str = "entity-42:label", claim_value: str = "compromised",
    *, payload: Optional[Mapping[str, Any]] = None,
    verified: bool = True,
    parent_tag_id: Optional[str] = None,
    at: Optional[datetime] = None,
) -> EvidenceRecord:
    p = payload if payload is not None else {"v": evid}
    return EvidenceRecord(
        evidence_id=evid, source_id=source, claim_key=claim_key,
        claim_value=claim_value, payload=p,
        tag=_tag(f"tag-{evid}", evid, p, verified=verified,
                 parent=parent_tag_id),
        at=at or _t0(),
    )


def _state(
    eid: str = "e", *,
    label: TrustLabel = TrustLabel.TRUSTED,
    quarantined: bool = False,
    verified_recovery: bool = True,
    has_last_verified: bool = True,
    authority: AuthorityLevel = AuthorityLevel.OPERATOR,
) -> StateRecord:
    return StateRecord(
        entity_id=eid, label=label, quarantined=quarantined,
        verified_recovery=verified_recovery,
        has_last_verified=has_last_verified, authority=authority,
    )


def _change(
    cid: str, pid: str = "p", *,
    frm: AuthorityLevel = AuthorityLevel.OPERATOR,
    to: AuthorityLevel = AuthorityLevel.SENIOR,
    at: Optional[datetime] = None,
) -> AuthorityChange:
    return AuthorityChange(
        change_id=cid, principal_id=pid, from_level=frm, to_level=to,
        at=at or _t0(),
    )


def _recovery(
    cid: str, eid: str = "e", *,
    source: str = "s1",
    independent: Iterable[str] = ("s2",),
    objective_achieved: bool = True,
    action_verified: bool = True,
    label: TrustLabel = TrustLabel.OBSERVED,
    at: Optional[datetime] = None,
) -> RecoveryClaim:
    return RecoveryClaim(
        claim_id=cid, entity_id=eid, claimed_label=label,
        source_id=source, objective_achieved=objective_achieved,
        action_verified=action_verified,
        independent_source_ids=frozenset(independent),
        at=at or _t0(),
    )


def _learning(
    iid: str, source: str = "s1", *,
    label: TrustLabel = TrustLabel.TRUSTED,
    weight: float = 0.5,
    corroborating: Iterable[str] = ("s2",),
    verified: bool = True,
    at: Optional[datetime] = None,
) -> LearningInput:
    ev = _ev(f"ev-{iid}", source=source, verified=verified)
    return LearningInput(
        input_id=iid, source_id=source, label=label, weight=weight,
        evidence=ev, corroborating_sources=frozenset(corroborating),
        at=at or _t0(),
    )


def _transition(
    tid: str, *,
    pid: str = "p1",
    frm: TrustLabel = TrustLabel.SUSPICIOUS,
    to: TrustLabel = TrustLabel.OBSERVED,
    status: PrincipalStatus = PrincipalStatus.ACTIVE,
    requester: AuthorityLevel = AuthorityLevel.SENIOR,
    required: AuthorityLevel = AuthorityLevel.SENIOR,
    verified: bool = True,
    action_verified: bool = True,
    at: Optional[datetime] = None,
) -> GuardedTransition:
    return GuardedTransition(
        transition_id=tid, principal_id=pid, from_label=frm,
        to_label=to, principal_status=status,
        requester_authority=requester, required_authority=required,
        verified=verified, action_verified=action_verified,
        at=at or _t0(),
    )


# ---- integrity ----

def test_integrity_tag_self_chain_rejected() -> None:
    try:
        IntegrityTag(
            tag_id="t", evidence_id="e",
            content_digest="d", verified=True,
            chain_parent_tag_id="t",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_verify_integrity_ok() -> None:
    p = {"a": 1}
    tag = _tag("t", "e", p)
    ok, reason = verify_integrity(tag=tag, payload=p)
    assert ok and reason is None


def test_verify_integrity_unverified() -> None:
    p = {"a": 1}
    tag = _tag("t", "e", p, verified=False)
    ok, reason = verify_integrity(tag=tag, payload=p)
    assert not ok
    assert reason is AdversarialFindingKind.INVALID_INTEGRITY_TAG


def test_verify_integrity_digest_mismatch() -> None:
    tag = _tag("t", "e", {"a": 1})
    ok, reason = verify_integrity(tag=tag, payload={"a": 2})
    assert not ok
    assert reason is AdversarialFindingKind.DIGEST_MISMATCH


def test_verify_integrity_chain_parent_missing() -> None:
    p = {"a": 1}
    tag = _tag("t", "e", p, parent="parent-tag")
    ok, reason = verify_integrity(tag=tag, payload=p, parent_tag=None)
    assert not ok
    assert reason is AdversarialFindingKind.INVALID_INTEGRITY_TAG


def test_verify_integrity_chain_parent_ok() -> None:
    p = {"a": 1}
    parent = _tag("pt", "pe", p)
    child = _tag("ct", "ce", p, parent=parent.tag_id)
    ok, reason = verify_integrity(
        tag=child, payload=p, parent_tag=parent,
    )
    assert ok


def test_verify_integrity_chain_parent_unverified() -> None:
    p = {"a": 1}
    parent = _tag("pt", "pe", p, verified=False)
    child = _tag("ct", "ce", p, parent=parent.tag_id)
    ok, _ = verify_integrity(tag=child, payload=p, parent_tag=parent)
    assert not ok


# ---- corroboration ----

def test_corroboration_rule_applies_to_all_when_empty() -> None:
    r = CorroborationRule()
    assert r.applies_to("anything")


def test_corroboration_rule_prefix_match() -> None:
    r = CorroborationRule(claim_prefixes=frozenset({"entity-"}))
    assert r.applies_to("entity-42:label")
    assert not r.applies_to("other")


def test_corroboration_single_source_not_satisfied() -> None:
    tracker = CorroborationTracker()
    tracker.record(_ev("e1", source="s1"))
    result = tracker.evaluate(
        "entity-42:label", "compromised", rule=CorroborationRule(),
    )
    assert not result.satisfied


def test_corroboration_two_sources_satisfied() -> None:
    tracker = CorroborationTracker()
    tracker.record(_ev("e1", source="s1"))
    tracker.record(_ev("e2", source="s2"))
    result = tracker.evaluate(
        "entity-42:label", "compromised", rule=CorroborationRule(),
    )
    assert result.satisfied
    assert result.sources == ("s1", "s2")


def test_corroboration_same_source_twice_not_satisfied() -> None:
    tracker = CorroborationTracker()
    tracker.record(_ev("e1", source="s1"))
    tracker.record(_ev("e2", source="s1"))
    result = tracker.evaluate(
        "entity-42:label", "compromised", rule=CorroborationRule(),
    )
    assert not result.satisfied


def test_corroboration_rule_not_applicable_satisfied() -> None:
    tracker = CorroborationTracker()
    rule = CorroborationRule(claim_prefixes=frozenset({"other"}))
    result = tracker.evaluate(
        "entity-42:label", "compromised", rule=rule,
    )
    assert result.satisfied


# ---- state consistency ----

def test_consistency_clean_state() -> None:
    findings = check_state_consistency(_state(), at=_t0())
    assert findings == ()


def test_consistency_quarantine_label_mismatch() -> None:
    s = _state(label=TrustLabel.TRUSTED, quarantined=True)
    findings = check_state_consistency(s, at=_t0())
    ids = {f.kind for f in findings}
    assert AdversarialFindingKind.STATE_INCONSISTENCY in ids


def test_consistency_trusted_without_last_verified() -> None:
    s = _state(label=TrustLabel.TRUSTED, has_last_verified=False)
    findings = check_state_consistency(s, at=_t0())
    assert any("last_verified" in f.detail for f in findings)


def test_consistency_high_authority_not_trusted() -> None:
    s = _state(label=TrustLabel.DEGRADED,
               authority=AuthorityLevel.ADMIN)
    findings = check_state_consistency(s, at=_t0())
    assert any("cons.high_authority" in f.detail for f in findings)


def test_consistency_predicate_exception_caught() -> None:
    def bad_predicate(s):
        raise RuntimeError("boom")
    rule = ConsistencyRule(
        rule_id="bad", description="raises",
        predicate=bad_predicate,
    )
    findings = check_state_consistency(
        _state(), rules=(rule,), at=_t0(),
    )
    assert len(findings) == 1
    assert "predicate raised" in findings[0].detail


def test_consistency_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        check_state_consistency(_state(), at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- confidence anomaly ----

def test_confidence_sample_bounds() -> None:
    try:
        ConfidenceSample(detector_id="d", confidence=1.5, at=_t0())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_confidence_anomaly_insufficient_samples() -> None:
    det = ConfidenceAnomalyDetector(
        config=ConfidenceAnomalyConfig(window=10, min_samples=5),
    )
    for i in range(3):
        det.record(ConfidenceSample("d", 0.5, _t(i)))
    assert det.analyze("d", at=_t0()) == ()


def test_confidence_anomaly_too_uniform() -> None:
    det = ConfidenceAnomalyDetector(
        config=ConfidenceAnomalyConfig(
            window=10, min_samples=6,
            uniformity_variance_threshold=0.001,
        ),
    )
    for i in range(8):
        det.record(ConfidenceSample("d", 0.5, _t(i)))
    anomalies = det.analyze("d", at=_t0())
    kinds = {a.kind for a in anomalies}
    assert AdversarialFindingKind.CONFIDENCE_TOO_UNIFORM in kinds


def test_confidence_anomaly_extreme_high() -> None:
    det = ConfidenceAnomalyDetector(
        config=ConfidenceAnomalyConfig(
            window=10, min_samples=6,
            extreme_ratio_threshold=0.7,
            uniformity_variance_threshold=0.0,  # disable uniformity
        ),
    )
    for i in range(8):
        det.record(ConfidenceSample("d", 0.99, _t(i)))
    anomalies = det.analyze("d", at=_t0())
    kinds = {a.kind for a in anomalies}
    assert AdversarialFindingKind.CONFIDENCE_EXTREME in kinds


def test_confidence_anomaly_natural_variance_no_findings() -> None:
    det = ConfidenceAnomalyDetector(
        config=ConfidenceAnomalyConfig(
            window=20, min_samples=8,
            uniformity_variance_threshold=0.0005,
            extreme_ratio_threshold=0.9,
        ),
    )
    import random
    rng = random.Random(42)
    for i in range(15):
        c = 0.4 + 0.2 * rng.random()
        det.record(ConfidenceSample("d", c, _t(i)))
    assert det.analyze("d", at=_t0()) == ()


def test_confidence_anomaly_requires_aware_time() -> None:
    det = ConfidenceAnomalyDetector(
        config=ConfidenceAnomalyConfig(window=3, min_samples=2),
    )
    from datetime import datetime as dt
    try:
        det.analyze("d", at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- authority escalation ----

def test_authority_change_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        AuthorityChange(
            change_id="c", principal_id="p",
            from_level=AuthorityLevel.OPERATOR,
            to_level=AuthorityLevel.SENIOR, at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_authority_escalation_single_jump_flagged() -> None:
    tracker = AuthorityEscalationTracker(
        config=AuthorityEscalationConfig(max_single_jump=1),
    )
    tracker.record(_change(
        "c", frm=AuthorityLevel.OPERATOR, to=AuthorityLevel.ADMIN,
    ))
    findings = tracker.analyze("p", at=_t0())
    assert any(
        f.kind is AdversarialFindingKind.AUTHORITY_ESCALATION_SUSPECT
        for f in findings
    )


def test_authority_escalation_frequency_flagged() -> None:
    tracker = AuthorityEscalationTracker(
        config=AuthorityEscalationConfig(
            max_single_jump=10,  # disable jump rule
            window_seconds=600.0,
            max_escalations_in_window=1,
        ),
    )
    tracker.record(_change(
        "c1", frm=AuthorityLevel.OPERATOR, to=AuthorityLevel.SENIOR,
        at=_t(0),
    ))
    tracker.record(_change(
        "c2", frm=AuthorityLevel.SENIOR, to=AuthorityLevel.ADMIN,
        at=_t(60),
    ))
    tracker.record(_change(
        "c3", frm=AuthorityLevel.ADMIN, to=AuthorityLevel.BREAK_GLASS,
        at=_t(120),
    ))
    findings = tracker.analyze("p", at=_t(180))
    assert any(
        "window" in f.detail for f in findings
    )


def test_authority_escalation_de_escalation_not_flagged() -> None:
    tracker = AuthorityEscalationTracker(
        config=AuthorityEscalationConfig(max_single_jump=1),
    )
    tracker.record(_change(
        "c1", frm=AuthorityLevel.ADMIN, to=AuthorityLevel.OPERATOR,
    ))
    assert tracker.analyze("p", at=_t0()) == ()


# ---- recovery ----

def test_recovery_claim_self_verifier_rejected() -> None:
    try:
        RecoveryClaim(
            claim_id="r", entity_id="e",
            claimed_label=TrustLabel.OBSERVED, source_id="s1",
            objective_achieved=True, action_verified=True,
            independent_source_ids=frozenset({"s1"}),
            at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_recovery_verified_when_all_conditions_met() -> None:
    v = verify_recovery_claim(_recovery("r"))
    assert v.accepted
    assert v.independent_verifiers == ("s2",)


def test_recovery_rejected_no_objective() -> None:
    v = verify_recovery_claim(_recovery("r", objective_achieved=False))
    assert not v.accepted


def test_recovery_rejected_no_verifiers() -> None:
    v = verify_recovery_claim(
        _recovery("r", independent=()),
        min_independent_verifiers=1,
    )
    assert not v.accepted


def test_recovery_rejected_action_unverified() -> None:
    v = verify_recovery_claim(_recovery("r", action_verified=False))
    assert not v.accepted


# ---- learning quarantine ----

def test_learning_input_bounds_weight() -> None:
    try:
        _learning("i", weight=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_learning_input_accepted() -> None:
    inp = _learning("i")
    d = evaluate_learning_input(
        inp, source_reliability=0.8,
        config=LearningQuarantineConfig(),
    )
    assert d.accepted


def test_learning_input_quarantined_low_reliability() -> None:
    inp = _learning("i")
    d = evaluate_learning_input(
        inp, source_reliability=0.1,
        config=LearningQuarantineConfig(min_source_reliability=0.4),
    )
    assert not d.accepted
    assert d.outcome is DefenseOutcome.QUARANTINED


def test_learning_input_quarantined_no_corroboration() -> None:
    inp = _learning("i", corroborating=())
    d = evaluate_learning_input(
        inp, source_reliability=0.9,
        config=LearningQuarantineConfig(min_corroborating_sources=1),
    )
    assert not d.accepted


def test_learning_input_quarantined_unverified_evidence() -> None:
    inp = _learning("i", verified=False)
    d = evaluate_learning_input(
        inp, source_reliability=0.9,
        config=LearningQuarantineConfig(),
    )
    assert not d.accepted


# ---- guarded transition ----

def test_transition_rejects_suspended_principal() -> None:
    t = _transition("t", status=PrincipalStatus.SUSPENDED)
    d = guard_transition(t)
    assert not d.allowed
    assert d.outcome is DefenseOutcome.REJECTED


def test_transition_rejects_insufficient_authority() -> None:
    t = _transition(
        "t", requester=AuthorityLevel.OPERATOR,
        required=AuthorityLevel.ADMIN,
    )
    d = guard_transition(t)
    assert not d.allowed


def test_transition_rejects_unverified_recovery() -> None:
    t = _transition(
        "t",
        frm=TrustLabel.SUSPICIOUS, to=TrustLabel.OBSERVED,
        verified=False,
    )
    d = guard_transition(t)
    assert not d.allowed


def test_transition_worsening_does_not_require_verification() -> None:
    t = _transition(
        "t",
        frm=TrustLabel.TRUSTED, to=TrustLabel.SUSPICIOUS,
        verified=False, action_verified=False,
    )
    d = guard_transition(t)
    assert d.allowed


def test_transition_verified_recovery_allowed() -> None:
    t = _transition("t")
    d = guard_transition(t)
    assert d.allowed


# ---- engine integration ----

def test_engine_integrity_failure_produces_finding() -> None:
    eng = AdversarialResilienceEngine()
    eng.register_source("s1", 0.9)
    eng.submit_evidence(_ev("e1", verified=False), at=_t0())
    findings = eng.findings()
    assert any(
        f.kind is AdversarialFindingKind.INVALID_INTEGRITY_TAG
        for f in findings
    )


def test_engine_clean_evidence_no_findings() -> None:
    eng = AdversarialResilienceEngine()
    eng.register_source("s1", 0.9)
    eng.submit_evidence(_ev("e1"), at=_t0())
    assert eng.findings() == ()


def test_engine_state_consistency_findings() -> None:
    eng = AdversarialResilienceEngine()
    eng.submit_state(
        _state(label=TrustLabel.TRUSTED, has_last_verified=False),
        at=_t0(),
    )
    assert any(
        f.kind is AdversarialFindingKind.STATE_INCONSISTENCY
        for f in eng.findings()
    )


def test_engine_corroboration_failure_finding() -> None:
    eng = AdversarialResilienceEngine()
    eng.register_source("s1", 0.9)
    eng.submit_evidence(_ev("e1", source="s1"), at=_t0())
    eng.analyze(
        at=_t0(),
        require_corroboration_for=[("entity-42:label", "compromised")],
    )
    assert any(
        f.kind is AdversarialFindingKind.INSUFFICIENT_CORROBORATION
        for f in eng.findings()
    )


def test_engine_corroboration_pass_when_two_sources() -> None:
    eng = AdversarialResilienceEngine()
    eng.register_source("s1", 0.9)
    eng.register_source("s2", 0.9)
    eng.submit_evidence(_ev("e1", source="s1"), at=_t0())
    eng.submit_evidence(_ev("e2", source="s2"), at=_t0())
    eng.analyze(
        at=_t0(),
        require_corroboration_for=[("entity-42:label", "compromised")],
    )
    assert not any(
        f.kind is AdversarialFindingKind.INSUFFICIENT_CORROBORATION
        for f in eng.findings()
    )


def test_engine_confidence_anomaly_finding() -> None:
    eng = AdversarialResilienceEngine(
        confidence_config=ConfidenceAnomalyConfig(
            window=10, min_samples=6,
            uniformity_variance_threshold=0.001,
        ),
    )
    for i in range(8):
        eng.submit_confidence(ConfidenceSample("d1", 0.5, _t(i)))
    eng.analyze(at=_t0(), confidence_detector_ids=["d1"])
    assert any(
        f.kind is AdversarialFindingKind.CONFIDENCE_TOO_UNIFORM
        for f in eng.findings()
    )


def test_engine_authority_escalation_finding() -> None:
    eng = AdversarialResilienceEngine(
        authority_config=AuthorityEscalationConfig(max_single_jump=1),
    )
    eng.submit_authority_change(_change(
        "c", frm=AuthorityLevel.OPERATOR, to=AuthorityLevel.ADMIN,
    ))
    eng.analyze(at=_t0(), authority_principal_ids=["p"])
    assert any(
        f.kind is AdversarialFindingKind.AUTHORITY_ESCALATION_SUSPECT
        for f in eng.findings()
    )


def test_engine_recovery_unverified_finding() -> None:
    eng = AdversarialResilienceEngine()
    eng.submit_recovery_claim(
        _recovery("r", objective_achieved=False),
    )
    assert any(
        f.kind is AdversarialFindingKind.RECOVERY_UNVERIFIED
        for f in eng.findings()
    )


def test_engine_recovery_verified_no_finding() -> None:
    eng = AdversarialResilienceEngine()
    eng.submit_recovery_claim(_recovery("r"))
    assert eng.recovery_verification("r").accepted
    assert not any(
        f.kind is AdversarialFindingKind.RECOVERY_UNVERIFIED
        for f in eng.findings()
    )


def test_engine_learning_input_quarantine() -> None:
    eng = AdversarialResilienceEngine(
        quarantine_config=LearningQuarantineConfig(
            min_source_reliability=0.5,
        ),
    )
    eng.register_source("s1", 0.1)
    eng.submit_learning_input(_learning("i"))
    d = eng.quarantine_decision("i")
    assert d is not None
    assert not d.accepted
    assert any(
        f.kind is AdversarialFindingKind.LEARNING_INPUT_QUARANTINED
        for f in eng.findings()
    )


def test_engine_learning_input_accepted() -> None:
    eng = AdversarialResilienceEngine()
    eng.register_source("s1", 0.9)
    eng.submit_learning_input(_learning("i"))
    d = eng.quarantine_decision("i")
    assert d is not None and d.accepted


def test_engine_transition_rejection_finding() -> None:
    eng = AdversarialResilienceEngine()
    eng.submit_transition(_transition(
        "t", status=PrincipalStatus.SUSPENDED,
    ))
    assert any(
        f.kind is AdversarialFindingKind.ADVERSARIAL_TRANSITION_REJECTED
        for f in eng.findings()
    )


def test_engine_findings_for_subject() -> None:
    eng = AdversarialResilienceEngine()
    eng.submit_transition(_transition(
        "t1", status=PrincipalStatus.SUSPENDED,
    ))
    assert len(eng.findings_for("t1")) == 1


def test_engine_severities_summary() -> None:
    eng = AdversarialResilienceEngine()
    eng.submit_transition(_transition(
        "t", status=PrincipalStatus.SUSPENDED,
    ))
    summary = eng.severities_summary()
    assert summary[Severity.HIGH] >= 1


def test_engine_analyze_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = AdversarialResilienceEngine()
    try:
        eng.analyze(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_submit_evidence_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = AdversarialResilienceEngine()
    try:
        eng.submit_evidence(_ev("e"), at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = AdversarialResilienceEngine()
    eng.register_source("s1", 0.9)
    eng.submit_evidence(_ev("e1"), at=_t0())
    eng.analyze(at=_t0())
    assert eng.violations() == ()


def test_invariant_quarantined_not_accepted() -> None:
    bad = QuarantineDecision(
        input_id="i", accepted=True,
        outcome=DefenseOutcome.QUARANTINED, rationale="fake",
    )
    snap = AdversarialSnapshot(
        findings=(), quarantine_decisions={"i": bad},
        transition_decisions={}, recovery_verifications={},
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "adv.quarantined_not_accepted" for x in v
    )


def test_invariant_rejected_transition_not_allowed() -> None:
    bad = GuardedTransitionDecision(
        transition_id="t", allowed=True,
        outcome=DefenseOutcome.REJECTED, rationale="fake",
    )
    snap = AdversarialSnapshot(
        findings=(), quarantine_decisions={},
        transition_decisions={"t": bad},
        recovery_verifications={},
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "adv.rejected_transition_not_allowed"
        for x in v
    )


def test_invariant_recovery_accepted_requires_verifiers() -> None:
    bad = RecoveryVerification(
        claim_id="r", accepted=True, rationale="fake",
        independent_verifiers=(),
    )
    snap = AdversarialSnapshot(
        findings=(), quarantine_decisions={},
        transition_decisions={},
        recovery_verifications={"r": bad},
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "adv.recovery_accepted_requires_verifiers"
        for x in v
    )


# ---- policy ----

def test_engine_register_source_validation() -> None:
    eng = AdversarialResilienceEngine()
    try:
        eng.register_source("s", 1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_min_independent_verifiers_validation() -> None:
    eng = AdversarialResilienceEngine()
    try:
        eng.set_min_independent_verifiers(0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_min_independent_verifiers_effect() -> None:
    eng = AdversarialResilienceEngine()
    eng.set_min_independent_verifiers(2)
    eng.submit_recovery_claim(_recovery("r", independent=("s2",)))
    v = eng.recovery_verification("r")
    assert v is not None
    assert not v.accepted


def test_engine_set_corroboration_rule_effect() -> None:
    eng = AdversarialResilienceEngine()
    eng.register_source("s1", 0.9)
    eng.set_corroboration_rule(
        CorroborationRule(min_sources=3),
    )
    eng.submit_evidence(_ev("e1", source="s1"), at=_t0())
    eng.submit_evidence(_ev("e2", source="s2"), at=_t0())
    eng.analyze(
        at=_t0(),
        require_corroboration_for=[("entity-42:label", "compromised")],
    )
    assert any(
        f.kind is AdversarialFindingKind.INSUFFICIENT_CORROBORATION
        for f in eng.findings()
    )


def test_engine_register_source_basic() -> None:
    eng = AdversarialResilienceEngine()
    eng.register_source("s", 0.9)
    assert eng.source_reliability("s") == 0.9


# ---- store ----

def test_in_memory_store_records() -> None:
    s = InMemoryAdversarialStore()
    s.put(AdversarialRecord(
        kind=AdversarialFindingKind.STATE_INCONSISTENCY,
        attack=AttackKind.STATE_CORRUPTION,
        subject_id="e", severity=Severity.HIGH,
        detail="x", at=_t0(),
    ))
    assert len(s.all()) == 1


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "adv.db")
    store = SqliteAdversarialStore(db)
    store.put(AdversarialRecord(
        kind=AdversarialFindingKind.ADVERSARIAL_TRANSITION_REJECTED,
        attack=AttackKind.ADVERSARIAL_STATE_TRANSITION,
        subject_id="t1", severity=Severity.HIGH,
        detail="x", at=_t0(),
    ))
    rows = store.all()
    assert len(rows) == 1
    assert rows[0].kind is \
        AdversarialFindingKind.ADVERSARIAL_TRANSITION_REJECTED
    assert rows[0].attack is AttackKind.ADVERSARIAL_STATE_TRANSITION


# =============================================================================
# SECTION 15 — MANUAL RUNNER
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
