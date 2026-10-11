"""
HYDRA POST-CORE — PHASE 6: DISTRIBUTED SECURITY STATE
========================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Node identity + trust model (reporting nodes may be untrusted)
  * Partition model (which nodes can see which)
  * StateReport with dual timestamps (observed_at, received_at)
  * Freshness model (time decay per report)
  * Divergence detection (weighted label disagreement)
  * Trust-weighted convergence / reconciliation
  * Most-defensible security state (MDS) computation under disagreement
  * Split-brain detection (contradictory partitions)
  * Visibility-gap detection (isolated observation)
  * Adversarial signal handling (quarantined sources can't force TRUSTED)
  * Explicit security-state transitions
  * Machine-checkable distributed-state invariants
  * In-memory and SQLite stores
  * Phase-6 engine facade
  * Full test suite + manual runner

Purpose: determine the most defensible security state when the
environment itself disagrees about reality.

This is NEW distributed security-state technology. It is not a
consensus algorithm (Raft/Paxos) — it is security-state reconciliation.

Run tests:
    python hydra_phase6_distributed_security_state.py
    pytest hydra_phase6_distributed_security_state.py -q
"""
from __future__ import annotations

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


def is_adversarial_label(label: TrustLabel) -> bool:
    return label in (TrustLabel.COMPROMISED, TrustLabel.QUARANTINED)


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


@dataclass(frozen=True)
class NodeIdentity:
    node_id: str
    region: str
    trust: float
    quarantined: bool = False

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id is required")
        if not self.region:
            raise ValueError("region is required")
        if not 0.0 <= self.trust <= 1.0:
            raise ValueError("trust must be within [0,1]")


@dataclass(frozen=True)
class PartitionView:
    """A partition groups nodes that can see each other's reports.

    A node in partition A cannot legitimately see reports produced by a
    node in partition B while the partition is active. If it does, that
    is a signal (possible injection or rejoin).
    """
    partition_id: str
    members: FrozenSet[str]

    def __post_init__(self) -> None:
        if not self.partition_id:
            raise ValueError("partition_id is required")
        if not self.members:
            raise ValueError("partition must have at least one member")


@dataclass(frozen=True)
class StateReport:
    report_id: str
    subject_id: str
    source_node_id: str
    label: TrustLabel
    score: float
    confidence: float
    observed_at: datetime
    received_at: datetime
    evidence: Evidence

    def __post_init__(self) -> None:
        if not self.report_id:
            raise ValueError("report_id is required")
        if not self.subject_id:
            raise ValueError("subject_id is required")
        if not self.source_node_id:
            raise ValueError("source_node_id is required")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be within [0,1]")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.received_at.tzinfo is None:
            raise ValueError("received_at must be timezone-aware")
        if self.received_at < self.observed_at:
            raise ValueError("received_at cannot be before observed_at")


# =============================================================================
# SECTION 3 — FRESHNESS / TRUST WEIGHTING
# =============================================================================


DEFAULT_HALF_LIFE_SECONDS: float = 300.0     # 5 minutes
DEFAULT_MAX_AGE_SECONDS: float = 1800.0      # 30 minutes hard cutoff


def freshness(
    observed_at: datetime,
    at: datetime,
    *,
    half_life_seconds: float = DEFAULT_HALF_LIFE_SECONDS,
) -> float:
    if half_life_seconds <= 0:
        raise ValueError("half_life_seconds must be > 0")
    age = (at - observed_at).total_seconds()
    if age <= 0:
        return 1.0
    return 0.5 ** (age / half_life_seconds)


def report_weight(
    report: StateReport,
    *,
    source_trust: float,
    at: datetime,
    half_life_seconds: float = DEFAULT_HALF_LIFE_SECONDS,
) -> float:
    """Effective weight of a report for aggregation."""
    if not 0.0 <= source_trust <= 1.0:
        raise ValueError("source_trust must be within [0,1]")
    f = freshness(report.observed_at, at, half_life_seconds=half_life_seconds)
    return source_trust * f * report.confidence


# =============================================================================
# SECTION 4 — DIVERGENCE DETECTION
# =============================================================================


class DivergenceKind(str, Enum):
    AGREE = "agree"
    MINOR = "minor"
    MAJOR = "major"
    CONTRADICTORY = "contradictory"
    INSUFFICIENT = "insufficient"


@dataclass(frozen=True)
class DivergenceResult:
    kind: DivergenceKind
    label_weights: Mapping[TrustLabel, float]
    total_weight: float
    winning_label: Optional[TrustLabel]
    winning_share: float
    divergence: float          # 0..1, 1 = total disagreement
    distinct_labels: int


def detect_divergence(
    label_weights: Mapping[TrustLabel, float],
) -> DivergenceResult:
    total = sum(label_weights.values())
    if total <= 0.0:
        return DivergenceResult(
            kind=DivergenceKind.INSUFFICIENT,
            label_weights=dict(label_weights),
            total_weight=0.0,
            winning_label=None,
            winning_share=0.0,
            divergence=1.0,
            distinct_labels=0,
        )

    winning_label = max(label_weights.items(), key=lambda kv: (kv[1], kv[0].value))[0]
    winning_weight = label_weights[winning_label]
    winning_share = winning_weight / total
    divergence = max(0.0, min(1.0, 1.0 - winning_share))
    distinct = sum(1 for v in label_weights.values() if v > 0.0)

    if distinct <= 1:
        kind = DivergenceKind.AGREE
    elif divergence <= 0.15:
        kind = DivergenceKind.MINOR
    elif divergence <= 0.40:
        kind = DivergenceKind.MAJOR
    else:
        kind = DivergenceKind.CONTRADICTORY

    return DivergenceResult(
        kind=kind,
        label_weights=dict(label_weights),
        total_weight=total,
        winning_label=winning_label,
        winning_share=winning_share,
        divergence=divergence,
        distinct_labels=distinct,
    )


def _defensive_pick(
    label_weights: Mapping[TrustLabel, float],
    *,
    min_share: float = 0.15,
) -> Tuple[TrustLabel, str]:
    """Choose the most defensible label from divergent weights.

    Policy:
      * If a label holds ≥ 70 % of weight → it wins outright.
      * Else, take all labels holding ≥ `min_share` weight and return the
        worse (higher-severity) one. This is the defensively correct
        answer when sources disagree.
    """
    total = sum(label_weights.values())
    if total <= 0.0:
        return TrustLabel.UNKNOWN, "no weight"
    top = max(label_weights.items(), key=lambda kv: kv[1])
    if top[1] / total >= 0.70:
        return top[0], f"weighted winner with {top[1] / total:.2f} share"
    candidates = [
        (lbl, w / total) for lbl, w in label_weights.items() if w / total >= min_share
    ]
    if not candidates:
        return top[0], "no candidate above min_share"
    candidate_labels = [c[0] for c in candidates]
    worst = candidate_labels[0]
    for lbl in candidate_labels[1:]:
        worst = worse_of(worst, lbl)
    return worst, f"defensive pick among {[l.value for l in candidate_labels]}"


# =============================================================================
# SECTION 5 — PARTITION MODEL
# =============================================================================


class PartitionTopology:
    """Tracks which nodes belong to which partition and whether the
    partitions can currently see each other."""

    def __init__(self) -> None:
        self._node_to_partition: Dict[str, str] = {}
        self._partitions: Dict[str, PartitionView] = {}
        self._links: Dict[Tuple[str, str], bool] = {}   # ordered pair -> visible

    def add_partition(self, partition: PartitionView) -> None:
        if partition.partition_id in self._partitions:
            raise ValueError(f"partition {partition.partition_id} already exists")
        for m in partition.members:
            if m in self._node_to_partition:
                raise ValueError(f"node {m} already in partition "
                                 f"{self._node_to_partition[m]}")
        self._partitions[partition.partition_id] = partition
        for m in partition.members:
            self._node_to_partition[m] = partition.partition_id

    def partition_of(self, node_id: str) -> Optional[str]:
        return self._node_to_partition.get(node_id)

    def partitions(self) -> Tuple[PartitionView, ...]:
        return tuple(self._partitions.values())

    def set_link(self, src_partition: str, dst_partition: str, visible: bool) -> None:
        if src_partition not in self._partitions:
            raise KeyError(f"unknown partition {src_partition}")
        if dst_partition not in self._partitions:
            raise KeyError(f"unknown partition {dst_partition}")
        self._links[(src_partition, dst_partition)] = visible

    def can_see(self, src_node: str, dst_node: str) -> bool:
        """Whether src_node can legitimately observe dst_node's reports."""
        a = self._node_to_partition.get(src_node)
        b = self._node_to_partition.get(dst_node)
        if a is None or b is None:
            return False
        if a == b:
            return True
        return self._links.get((a, b), False)


# =============================================================================
# SECTION 6 — RECONCILIATION
# =============================================================================


class ReconciledLabel(str, Enum):
    UNKNOWN = "unknown"
    OBSERVED = "observed"
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class ReconciledState:
    subject_id: str
    label: TrustLabel
    defensibility: float          # 0..1
    divergence: DivergenceResult
    supporting_weight: float
    used_report_ids: Tuple[str, ...]
    dropped_report_ids: Tuple[str, ...]
    split_brain: bool
    visibility_gap: bool
    adversarial_signal: bool
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 0.0 <= self.defensibility <= 1.0:
            raise ValueError("defensibility must be within [0,1]")


@dataclass(frozen=True)
class ReconciliationPolicy:
    half_life_seconds: float = DEFAULT_HALF_LIFE_SECONDS
    max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS
    min_source_trust: float = 0.15      # below this, source is dropped
    trusted_source_threshold: float = 0.70
    escalation_floor_severity: TrustLabel = TrustLabel.SUSPICIOUS
    split_brain_min_partitions: int = 2

    def __post_init__(self) -> None:
        if self.half_life_seconds <= 0:
            raise ValueError("half_life_seconds must be > 0")
        if self.max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be > 0")
        if not 0.0 <= self.min_source_trust <= 1.0:
            raise ValueError("min_source_trust must be within [0,1]")
        if not 0.0 <= self.trusted_source_threshold <= 1.0:
            raise ValueError("trusted_source_threshold must be within [0,1]")
        if self.split_brain_min_partitions < 2:
            raise ValueError("split_brain_min_partitions must be >= 2")


def reconcile(
    subject_id: str,
    reports: Iterable[StateReport],
    nodes: Mapping[str, NodeIdentity],
    topology: PartitionTopology,
    *,
    at: datetime,
    policy: ReconciliationPolicy = ReconciliationPolicy(),
) -> ReconciledState:
    if at.tzinfo is None:
        raise ValueError("at must be timezone-aware")

    used: List[str] = []
    dropped: List[str] = []
    label_weights: Dict[TrustLabel, float] = {}
    label_sources: Dict[TrustLabel, set] = {}
    partition_ids: set = set()
    adversarial_signal = False

    for r in reports:
        node = nodes.get(r.source_node_id)
        if node is None:
            dropped.append(r.report_id)
            continue
        age = (at - r.observed_at).total_seconds()
        if age < 0 or age > policy.max_age_seconds:
            dropped.append(r.report_id)
            continue
        if node.trust < policy.min_source_trust:
            dropped.append(r.report_id)
            continue

        # Quarantined source is dropped, but a quarantined source
        # reporting a *better* label than UNKNOWN/QUARANTINED is treated
        # as adversarial evidence.
        if node.quarantined:
            dropped.append(r.report_id)
            if label_severity(r.label) < label_severity(TrustLabel.COMPROMISED):
                adversarial_signal = True
            continue

        w = report_weight(
            r, source_trust=node.trust, at=at,
            half_life_seconds=policy.half_life_seconds,
        )
        if w <= 0.0:
            dropped.append(r.report_id)
            continue

        label_weights[r.label] = label_weights.get(r.label, 0.0) + w
        label_sources.setdefault(r.label, set()).add(r.source_node_id)
        used.append(r.report_id)
        pid = topology.partition_of(r.source_node_id)
        if pid is not None:
            partition_ids.add(pid)

        # Escalation signal: trusted source says COMPROMISED/QUARANTINED
        if (node.trust >= policy.trusted_source_threshold
                and is_adversarial_label(r.label)):
            adversarial_signal = True

    divergence = detect_divergence(label_weights)

    # Base label from weighted reconciliation
    if divergence.total_weight <= 0.0:
        base_label = TrustLabel.UNKNOWN
        rationale = "no usable reports"
    else:
        picked, why = _defensive_pick(label_weights)
        base_label = picked
        rationale = f"defensive reconciliation: {why}"
        if base_label is TrustLabel.TRUSTED \
           and len(label_sources.get(TrustLabel.TRUSTED, ())) < 2:
            base_label = TrustLabel.OBSERVED
            rationale += (
                " | downgraded: TRUSTED requires corroboration from "
                "2+ independent sources, only "
                f"{len(label_sources.get(TrustLabel.TRUSTED, ()))} seen"
            )

    # Trusted-source escalation: if a trusted source saw compromise,
    # never return anything below SUSPICIOUS.
    escalated = False
    if adversarial_signal and label_severity(base_label) < label_severity(
        policy.escalation_floor_severity
    ):
        base_label = policy.escalation_floor_severity
        escalated = True
        rationale += " | escalated by trusted-source compromise signal"

    # Partition-aware flags
    split_brain = len(partition_ids) >= policy.split_brain_min_partitions

    # Visibility gap: subject has exactly one partition reporting on it,
    # and other partitions contain nodes that are known to be able to see
    # the subject but aren't reporting. We conservatively detect as:
    # exactly one partition, and at least one other partition exists.
    all_partitions = {p.partition_id for p in topology.partitions()}
    visibility_gap = (
        len(partition_ids) == 1
        and len(all_partitions) > 1
    )

    # Defensibility
    support = min(1.0, divergence.total_weight)
    freshness_factor = (
        1.0 if not reports else
        max((freshness(r.observed_at, at,
                       half_life_seconds=policy.half_life_seconds)
             for r in reports if r.report_id in used), default=0.0)
    )
    partition_factor = 1.0
    if split_brain:
        partition_factor = 0.6
    if visibility_gap:
        partition_factor = min(partition_factor, 0.7)

    defensibility = max(0.0, min(1.0,
        support * (1.0 - divergence.divergence)
        * freshness_factor * partition_factor
    ))

    if escalation if False else False:  # placeholder to keep linter calm
        pass

    return ReconciledState(
        subject_id=subject_id,
        label=base_label,
        defensibility=defensibility,
        divergence=divergence,
        supporting_weight=divergence.total_weight,
        used_report_ids=tuple(used),
        dropped_report_ids=tuple(dropped),
        split_brain=split_brain,
        visibility_gap=visibility_gap,
        adversarial_signal=adversarial_signal,
        rationale=rationale,
        at=at,
    )


# =============================================================================
# SECTION 7 — TRANSITIONS
# =============================================================================


class TransitionOutcome(str, Enum):
    ALLOWED = "allowed"
    REJECTED_INVALID = "rejected_invalid"
    REQUIRES_VERIFICATION = "requires_verification"


_ALLOWED_LABEL_EDGES: Mapping[TrustLabel, FrozenSet[TrustLabel]] = {
    TrustLabel.UNKNOWN: frozenset({
        TrustLabel.OBSERVED, TrustLabel.DEGRADED, TrustLabel.SUSPICIOUS,
        TrustLabel.TRUSTED, TrustLabel.COMPROMISED,
        TrustLabel.QUARANTINED,
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
    subject_id: str
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
    reaching_trust_from_unknown = (
        req.from_label is TrustLabel.UNKNOWN
        and req.to_label is TrustLabel.TRUSTED
    )
    if (going_better or reaching_trust_from_unknown) and not req.verified:
        return TransitionDecision(
            TransitionOutcome.REQUIRES_VERIFICATION,
            "recovery transitions require verification",
        )
    return TransitionDecision(TransitionOutcome.ALLOWED, "permitted")


# =============================================================================
# SECTION 8 — INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class DistributedSnapshot:
    reconciliations: Mapping[str, ReconciledState]
    nodes: Mapping[str, NodeIdentity]
    topology: PartitionTopology
    reports: Tuple[StateReport, ...]


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class DistributedInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[DistributedSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_trusted_under_split_brain(
    snap: DistributedSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for sid, rs in snap.reconciliations.items():
        if rs.split_brain and rs.label is TrustLabel.TRUSTED:
            out.append(InvariantViolation(
                invariant_id="dist.no_trusted_under_split_brain",
                severity=InvariantSeverity.CRITICAL,
                subject_id=sid,
                detail=(
                    f"subject {sid} marked TRUSTED while partitions disagree"
                ),
            ))
    return tuple(out)


def _inv_compromised_source_not_authoritative(
    snap: DistributedSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for r in snap.reports:
        node = snap.nodes.get(r.source_node_id)
        if node is None or not node.quarantined:
            continue
        # A quarantined source must never have been used.
        for sid, rs in snap.reconciliations.items():
            if sid != r.subject_id:
                continue
            if r.report_id in rs.used_report_ids:
                out.append(InvariantViolation(
                    invariant_id="dist.quarantined_source_not_authoritative",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=r.source_node_id,
                    detail=(
                        f"quarantined node {r.source_node_id} contributed "
                        f"report {r.report_id} to {sid}"
                    ),
                ))
    return tuple(out)


def _inv_split_brain_flagged(
    snap: DistributedSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for sid, rs in snap.reconciliations.items():
        partition_ids = set()
        for r in snap.reports:
            if r.subject_id != sid:
                continue
            if r.report_id not in rs.used_report_ids:
                continue
            pid = snap.topology.partition_of(r.source_node_id)
            if pid is not None:
                partition_ids.add(pid)
        if len(partition_ids) >= 2 and not rs.split_brain:
            out.append(InvariantViolation(
                invariant_id="dist.split_brain_flagged",
                severity=InvariantSeverity.HIGH,
                subject_id=sid,
                detail=(
                    f"subject {sid} has reports from {sorted(partition_ids)} "
                    f"but split_brain is not flagged"
                ),
            ))
    return tuple(out)


def _inv_no_trusted_without_quorum(
    snap: DistributedSnapshot,
    *,
    min_reports: int = 2,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for sid, rs in snap.reconciliations.items():
        if rs.label is not TrustLabel.TRUSTED:
            continue
        if len(rs.used_report_ids) < min_reports:
            out.append(InvariantViolation(
                invariant_id="dist.no_trusted_without_quorum",
                severity=InvariantSeverity.HIGH,
                subject_id=sid,
                detail=(
                    f"subject {sid} TRUSTED with only "
                    f"{len(rs.used_report_ids)} supporting report(s)"
                ),
            ))
    return tuple(out)


def _inv_adversarial_signal_not_silent(
    snap: DistributedSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for sid, rs in snap.reconciliations.items():
        if rs.adversarial_signal and rs.label is TrustLabel.TRUSTED:
            out.append(InvariantViolation(
                invariant_id="dist.adversarial_signal_not_silent",
                severity=InvariantSeverity.CRITICAL,
                subject_id=sid,
                detail=(
                    f"subject {sid} TRUSTED despite adversarial signal"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[DistributedInvariant, ...] = (
    DistributedInvariant(
        invariant_id="dist.no_trusted_under_split_brain",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_trusted_under_split_brain,
        description="Split-brain subjects must not be TRUSTED.",
    ),
    DistributedInvariant(
        invariant_id="dist.quarantined_source_not_authoritative",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_compromised_source_not_authoritative,
        description="Quarantined nodes must never contribute to state.",
    ),
    DistributedInvariant(
        invariant_id="dist.split_brain_flagged",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_split_brain_flagged,
        description="Multi-partition reports must set the split_brain flag.",
    ),
    DistributedInvariant(
        invariant_id="dist.no_trusted_without_quorum",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_no_trusted_without_quorum,
        description="TRUSTED requires at least 2 supporting reports.",
    ),
    DistributedInvariant(
        invariant_id="dist.adversarial_signal_not_silent",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_adversarial_signal_not_silent,
        description="Adversarial signals must not be silently ignored.",
    ),
)


def check_invariants(
    snap: DistributedSnapshot,
    invariants: Iterable[DistributedInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 9 — STORES
# =============================================================================


@dataclass(frozen=True)
class ReconciledRecord:
    subject_id: str
    label: TrustLabel
    defensibility: float
    split_brain: bool
    visibility_gap: bool
    adversarial_signal: bool
    at: datetime


class DistributedStateStore(Protocol):
    def get(self, subject_id: str) -> Optional[ReconciledRecord]: ...
    def put(self, record: ReconciledRecord) -> None: ...
    def all(self) -> Tuple[ReconciledRecord, ...]: ...


class InMemoryDistributedStore:
    def __init__(self) -> None:
        self._data: Dict[str, ReconciledRecord] = {}

    def get(self, subject_id: str) -> Optional[ReconciledRecord]:
        return self._data.get(subject_id)

    def put(self, record: ReconciledRecord) -> None:
        existing = self._data.get(record.subject_id)
        if existing is not None and existing.at > record.at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.subject_id] = record

    def all(self) -> Tuple[ReconciledRecord, ...]:
        return tuple(self._data.values())


class SqliteDistributedStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dist_reconciled (
                subject_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                defensibility REAL NOT NULL,
                split_brain INTEGER NOT NULL,
                visibility_gap INTEGER NOT NULL,
                adversarial_signal INTEGER NOT NULL,
                at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dist_reports (
                report_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, subject_id: str) -> Optional[ReconciledRecord]:
        row = self._conn.execute(
            "SELECT label, defensibility, split_brain, visibility_gap, "
            "adversarial_signal, at FROM dist_reconciled WHERE subject_id = ?",
            (subject_id,),
        ).fetchone()
        if row is None:
            return None
        return ReconciledRecord(
            subject_id=subject_id,
            label=TrustLabel(row[0]),
            defensibility=float(row[1]),
            split_brain=bool(row[2]),
            visibility_gap=bool(row[3]),
            adversarial_signal=bool(row[4]),
            at=datetime.fromisoformat(row[5]),
        )

    def put(self, record: ReconciledRecord) -> None:
        existing = self.get(record.subject_id)
        if existing is not None and existing.at > record.at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO dist_reconciled
              (subject_id, label, defensibility, split_brain, visibility_gap,
               adversarial_signal, at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(subject_id) DO UPDATE SET
              label=excluded.label,
              defensibility=excluded.defensibility,
              split_brain=excluded.split_brain,
              visibility_gap=excluded.visibility_gap,
              adversarial_signal=excluded.adversarial_signal,
              at=excluded.at
            """,
            (
                record.subject_id, record.label.value, record.defensibility,
                int(record.split_brain), int(record.visibility_gap),
                int(record.adversarial_signal), record.at.isoformat(),
            ),
        )
        self._conn.commit()

    def all(self) -> Tuple[ReconciledRecord, ...]:
        rows = self._conn.execute(
            "SELECT subject_id FROM dist_reconciled"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_report(self, report: StateReport) -> None:
        payload = {
            "report_id": report.report_id,
            "subject_id": report.subject_id,
            "source_node_id": report.source_node_id,
            "label": report.label.value,
            "score": report.score,
            "confidence": report.confidence,
            "observed_at": report.observed_at.isoformat(),
            "received_at": report.received_at.isoformat(),
            "evidence_id": report.evidence.evidence_id,
            "evidence_source": report.evidence.source,
            "evidence_confidence": report.evidence.confidence,
            "evidence_observed_at": report.evidence.observed_at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO dist_reports (report_id, payload_json) "
            "VALUES (?, ?)",
            (report.report_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def get_report(self, report_id: str) -> Optional[StateReport]:
        row = self._conn.execute(
            "SELECT payload_json FROM dist_reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()
        if row is None:
            return None
        p = json.loads(row[0])
        return StateReport(
            report_id=p["report_id"],
            subject_id=p["subject_id"],
            source_node_id=p["source_node_id"],
            label=TrustLabel(p["label"]),
            score=float(p["score"]),
            confidence=float(p["confidence"]),
            observed_at=datetime.fromisoformat(p["observed_at"]),
            received_at=datetime.fromisoformat(p["received_at"]),
            evidence=Evidence(
                evidence_id=p["evidence_id"],
                source=p["evidence_source"],
                confidence=float(p["evidence_confidence"]),
                observed_at=datetime.fromisoformat(p["evidence_observed_at"]),
                payload={},
            ),
        )


# =============================================================================
# SECTION 10 — ENGINE
# =============================================================================


class DistributedSecurityStateEngine:
    """Reconciles multiple, possibly-conflicting security-state reports
    across a partitioned environment.

    Produces per-subject `ReconciledState` with a defensibility score.
    """

    def __init__(
        self,
        *,
        store: Optional[DistributedStateStore] = None,
        policy: Optional[ReconciliationPolicy] = None,
    ) -> None:
        self._store: DistributedStateStore = store or InMemoryDistributedStore()
        self._policy = policy or ReconciliationPolicy()
        self._nodes: Dict[str, NodeIdentity] = {}
        self._topology = PartitionTopology()
        self._reports: Dict[str, StateReport] = {}
        self._reconciliations: Dict[str, ReconciledState] = {}
        self._previous_labels: Dict[str, TrustLabel] = {}
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def register_node(self, node: NodeIdentity) -> None:
        if node.node_id in self._nodes:
            raise ValueError(f"node {node.node_id} already registered")
        self._nodes[node.node_id] = node

    def add_partition(self, partition: PartitionView) -> None:
        # ensure all members are registered
        for m in partition.members:
            if m not in self._nodes:
                raise KeyError(f"partition member {m} not registered")
        self._topology.add_partition(partition)

    def set_partition_link(self, a: str, b: str, visible: bool) -> None:
        self._topology.set_link(a, b, visible)

    def report(self, report: StateReport) -> None:
        if report.source_node_id not in self._nodes:
            raise KeyError(f"source node {report.source_node_id} not registered")
        self._reports[report.report_id] = report
        if isinstance(self._store, SqliteDistributedStore):
            self._store.put_report(report)

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[ReconciledRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        subjects = sorted({r.subject_id for r in self._reports.values()})
        records: List[ReconciledRecord] = []

        for sid in subjects:
            subject_reports = [
                r for r in self._reports.values() if r.subject_id == sid
            ]
            rs = reconcile(
                sid, subject_reports, self._nodes, self._topology,
                at=at, policy=self._policy,
            )

            # transition enforcement against previous label
            previous = self._previous_labels.get(sid, TrustLabel.UNKNOWN)
            if previous is not rs.label:
                verified = rs.defensibility >= 0.6 and not rs.split_brain
                decision = evaluate_transition(TransitionRequest(
                    subject_id=sid, from_label=previous, to_label=rs.label,
                    reason="recompute", verified=verified,
                ))
                if decision.outcome in (
                    TransitionOutcome.REJECTED_INVALID,
                    TransitionOutcome.REQUIRES_VERIFICATION,
                ):
                    rs = ReconciledState(
                        subject_id=rs.subject_id,
                        label=previous,
                        defensibility=rs.defensibility,
                        divergence=rs.divergence,
                        supporting_weight=rs.supporting_weight,
                        used_report_ids=rs.used_report_ids,
                        dropped_report_ids=rs.dropped_report_ids,
                        split_brain=rs.split_brain,
                        visibility_gap=rs.visibility_gap,
                        adversarial_signal=rs.adversarial_signal,
                        rationale=rs.rationale + " | transition held",
                        at=rs.at,
                    )

            self._reconciliations[sid] = rs
            self._previous_labels[sid] = rs.label
            record = ReconciledRecord(
                subject_id=sid, label=rs.label,
                defensibility=rs.defensibility,
                split_brain=rs.split_brain,
                visibility_gap=rs.visibility_gap,
                adversarial_signal=rs.adversarial_signal,
                at=at,
            )
            self._store.put(record)
            records.append(record)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def reconciliation(self, subject_id: str) -> Optional[ReconciledState]:
        return self._reconciliations.get(subject_id)

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return check_invariants(self.snapshot())

    def snapshot(self) -> DistributedSnapshot:
        return DistributedSnapshot(
            reconciliations=dict(self._reconciliations),
            nodes=dict(self._nodes),
            topology=self._topology,
            reports=tuple(self._reports.values()),
        )

    def state(self, subject_id: str) -> Optional[ReconciledRecord]:
        return self._store.get(subject_id)


# =============================================================================
# SECTION 11 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ev(at: datetime, conf: float = 0.9) -> Evidence:
    return Evidence(evidence_id="e", source="test", confidence=conf,
                    observed_at=at, payload={})


def _node(nid: str, trust: float = 0.9, quarantined: bool = False,
          region: str = "r") -> NodeIdentity:
    return NodeIdentity(node_id=nid, region=region, trust=trust,
                        quarantined=quarantined)


def _report(rid: str, subject: str, source: str, label: TrustLabel,
            *, at: Optional[datetime] = None, score: float = 0.5,
            conf: float = 0.9) -> StateReport:
    t = at or _t0()
    return StateReport(
        report_id=rid, subject_id=subject, source_node_id=source,
        label=label, score=score, confidence=conf,
        observed_at=t, received_at=t, evidence=_ev(t),
    )


def _topology_single(*node_ids: str) -> PartitionTopology:
    topo = PartitionTopology()
    topo.add_partition(PartitionView("p1", frozenset(node_ids)))
    return topo


def _topology_split(a: Tuple[str, ...], b: Tuple[str, ...]) -> PartitionTopology:
    topo = PartitionTopology()
    topo.add_partition(PartitionView("pa", frozenset(a)))
    topo.add_partition(PartitionView("pb", frozenset(b)))
    topo.set_link("pa", "pb", False)
    topo.set_link("pb", "pa", False)
    return topo


# ---- domain tests ---------------------------------------------------------

def test_node_trust_bounds() -> None:
    try:
        NodeIdentity(node_id="n", region="r", trust=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_report_received_before_observed_rejected() -> None:
    from datetime import timezone
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    earlier = t - timedelta(seconds=1)
    try:
        StateReport(
            report_id="r", subject_id="s", source_node_id="n",
            label=TrustLabel.TRUSTED, score=0.9, confidence=0.9,
            observed_at=t, received_at=earlier, evidence=_ev(t),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_report_confidence_bounds() -> None:
    try:
        StateReport(
            report_id="r", subject_id="s", source_node_id="n",
            label=TrustLabel.TRUSTED, score=0.9, confidence=1.5,
            observed_at=_t0(), received_at=_t0(), evidence=_ev(_t0()),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_partition_requires_members() -> None:
    try:
        PartitionView("p", frozenset())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_label_severity_order() -> None:
    assert label_severity(TrustLabel.TRUSTED) < label_severity(TrustLabel.DEGRADED)
    assert label_severity(TrustLabel.DEGRADED) < label_severity(TrustLabel.SUSPICIOUS)
    assert label_severity(TrustLabel.SUSPICIOUS) < label_severity(TrustLabel.COMPROMISED)
    assert label_severity(TrustLabel.COMPROMISED) < label_severity(TrustLabel.QUARANTINED)


def test_worse_of() -> None:
    assert worse_of(TrustLabel.TRUSTED, TrustLabel.SUSPICIOUS) is TrustLabel.SUSPICIOUS
    assert worse_of(TrustLabel.COMPROMISED, TrustLabel.DEGRADED) is TrustLabel.COMPROMISED


# ---- freshness / weight ---------------------------------------------------

def test_freshness_immediate_is_one() -> None:
    assert freshness(_t0(), _t0()) == 1.0


def test_freshness_halves_at_half_life() -> None:
    later = _t0() + timedelta(seconds=DEFAULT_HALF_LIFE_SECONDS)
    f = freshness(_t0(), later, half_life_seconds=DEFAULT_HALF_LIFE_SECONDS)
    assert abs(f - 0.5) < 1e-9


def test_freshness_never_negative() -> None:
    way_later = _t0() + timedelta(days=100)
    f = freshness(_t0(), way_later, half_life_seconds=DEFAULT_HALF_LIFE_SECONDS)
    assert f >= 0.0


def test_freshness_requires_positive_half_life() -> None:
    try:
        freshness(_t0(), _t0(), half_life_seconds=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_report_weight_scales_with_source_trust() -> None:
    r = _report("r", "s", "n", TrustLabel.TRUSTED)
    w_low = report_weight(r, source_trust=0.2, at=_t0())
    w_high = report_weight(r, source_trust=1.0, at=_t0())
    assert w_high > w_low


# ---- divergence ------------------------------------------------------------

def test_divergence_no_reports_insufficient() -> None:
    d = detect_divergence({})
    assert d.kind is DivergenceKind.INSUFFICIENT


def test_divergence_single_label_agree() -> None:
    d = detect_divergence({TrustLabel.TRUSTED: 1.0})
    assert d.kind is DivergenceKind.AGREE
    assert d.winning_label is TrustLabel.TRUSTED


def test_divergence_minor_disagreement() -> None:
    d = detect_divergence({
        TrustLabel.TRUSTED: 0.90,
        TrustLabel.OBSERVED: 0.10,
    })
    assert d.kind in (DivergenceKind.MINOR, DivergenceKind.MAJOR)


def test_divergence_contradictory() -> None:
    d = detect_divergence({
        TrustLabel.TRUSTED: 0.5,
        TrustLabel.COMPROMISED: 0.5,
    })
    assert d.kind is DivergenceKind.CONTRADICTORY
    assert d.divergence >= 0.5


# ---- defensive pick -------------------------------------------------------

def test_defensive_pick_weighted_winner() -> None:
    label, _ = _defensive_pick({TrustLabel.TRUSTED: 8.0,
                                TrustLabel.SUSPICIOUS: 2.0})
    assert label is TrustLabel.TRUSTED


def test_defensive_pick_when_balanced_picks_worse() -> None:
    label, _ = _defensive_pick({TrustLabel.TRUSTED: 0.55,
                                TrustLabel.SUSPICIOUS: 0.45})
    # TRUSTED holds >=0.70? no → defensive pick worse
    # 0.55/1.0=0.55 < 0.70 → defensive → worse of the two
    assert label is TrustLabel.SUSPICIOUS


def test_defensive_pick_empty() -> None:
    label, _ = _defensive_pick({})
    assert label is TrustLabel.UNKNOWN


# ---- partition topology ---------------------------------------------------

def test_partition_topology_can_see_within() -> None:
    topo = _topology_single("a", "b")
    assert topo.can_see("a", "b")
    assert topo.can_see("b", "a")


def test_partition_topology_cannot_see_across_when_blocked() -> None:
    topo = _topology_split(("a",), ("b",))
    assert not topo.can_see("a", "b")
    assert not topo.can_see("b", "a")


def test_partition_topology_can_see_across_when_visible() -> None:
    topo = PartitionTopology()
    topo.add_partition(PartitionView("pa", frozenset({"a"})))
    topo.add_partition(PartitionView("pb", frozenset({"b"})))
    topo.set_link("pa", "pb", True)
    assert topo.can_see("a", "b")


def test_partition_unknown_node_returns_false() -> None:
    topo = _topology_single("a")
    assert not topo.can_see("a", "ghost")


# ---- reconcile basic -------------------------------------------------------

def test_reconcile_no_reports_unknown() -> None:
    topo = _topology_single("n1")
    rs = reconcile("sub", [], {"n1": _node("n1")}, topo, at=_t0())
    assert rs.label is TrustLabel.UNKNOWN
    assert rs.defensibility == 0.0


def test_reconcile_agreement_trusted() -> None:
    topo = _topology_single("n1", "n2", "n3")
    nodes = {n: _node(n, trust=0.95) for n in ("n1", "n2", "n3")}
    reports = [
        _report("r1", "sub", "n1", TrustLabel.TRUSTED),
        _report("r2", "sub", "n2", TrustLabel.TRUSTED),
        _report("r3", "sub", "n3", TrustLabel.TRUSTED),
    ]
    rs = reconcile("sub", reports, nodes, topo, at=_t0())
    assert rs.label is TrustLabel.TRUSTED
    assert rs.divergence.kind is DivergenceKind.AGREE


def test_reconcile_defensive_on_disagreement() -> None:
    topo = _topology_single("n1", "n2")
    nodes = {"n1": _node("n1", trust=0.9), "n2": _node("n2", trust=0.9)}
    reports = [
        _report("r1", "sub", "n1", TrustLabel.TRUSTED),
        _report("r2", "sub", "n2", TrustLabel.SUSPICIOUS),
    ]
    rs = reconcile("sub", reports, nodes, topo, at=_t0())
    # 50/50 → defensive → worse → SUSPICIOUS
    assert rs.label is TrustLabel.SUSPICIOUS


def test_reconcile_drops_stale_reports() -> None:
    topo = _topology_single("n1", "n2")
    nodes = {"n1": _node("n1"), "n2": _node("n2")}
    old = _t0() - timedelta(hours=2)
    reports = [
        _report("r1", "sub", "n1", TrustLabel.TRUSTED, at=old),
        _report("r2", "sub", "n2", TrustLabel.TRUSTED),
    ]
    rs = reconcile("sub", reports, nodes, topo, at=_t0())
    assert "r1" in rs.dropped_report_ids
    assert "r2" in rs.used_report_ids


def test_reconcile_drops_untrusted_source() -> None:
    topo = _topology_single("n1", "n2")
    nodes = {"n1": _node("n1", trust=0.95),
             "n2": _node("n2", trust=0.05)}
    reports = [
        _report("r1", "sub", "n1", TrustLabel.TRUSTED),
        _report("r2", "sub", "n2", TrustLabel.COMPROMISED),
    ]
    rs = reconcile("sub", reports, nodes, topo, at=_t0())
    assert "r2" in rs.dropped_report_ids


def test_reconcile_drops_quarantined_source_and_flags_adversarial() -> None:
    topo = _topology_single("n1", "n2")
    nodes = {"n1": _node("n1", trust=0.9),
             "n2": _node("n2", trust=0.9, quarantined=True)}
    reports = [
        _report("r1", "sub", "n1", TrustLabel.TRUSTED),
        _report("r2", "sub", "n2", TrustLabel.TRUSTED),   # quarantined source
    ]
    rs = reconcile("sub", reports, nodes, topo, at=_t0())
    assert "r2" in rs.dropped_report_ids
    assert rs.adversarial_signal is True


def test_reconcile_trusted_source_compromise_escalates() -> None:
    topo = _topology_single("n1", "n2", "n3")
    nodes = {
        "n1": _node("n1", trust=0.95),
        "n2": _node("n2", trust=0.95),
        "n3": _node("n3", trust=0.95),
    }
    reports = [
        _report("r1", "sub", "n1", TrustLabel.TRUSTED),
        _report("r2", "sub", "n2", TrustLabel.TRUSTED),
        _report("r3", "sub", "n3", TrustLabel.COMPROMISED),
    ]
    rs = reconcile("sub", reports, nodes, topo, at=_t0())
    # trusted source reports compromise → must escalate
    assert label_severity(rs.label) >= label_severity(TrustLabel.SUSPICIOUS)
    assert rs.adversarial_signal


def test_reconcile_split_brain_flag() -> None:
    topo = _topology_split(("n1", "n2"), ("n3", "n4"))
    nodes = {n: _node(n, trust=0.9) for n in ("n1", "n2", "n3", "n4")}
    reports = [
        _report("r1", "sub", "n1", TrustLabel.TRUSTED),
        _report("r2", "sub", "n2", TrustLabel.TRUSTED),
        _report("r3", "sub", "n3", TrustLabel.SUSPICIOUS),
        _report("r4", "sub", "n4", TrustLabel.SUSPICIOUS),
    ]
    rs = reconcile("sub", reports, nodes, topo, at=_t0())
    assert rs.split_brain is True


def test_reconcile_visibility_gap_flag() -> None:
    topo = _topology_split(("n1", "n2"), ("n3", "n4"))
    nodes = {n: _node(n, trust=0.9) for n in ("n1", "n2", "n3", "n4")}
    reports = [
        _report("r1", "sub", "n1", TrustLabel.TRUSTED),
        _report("r2", "sub", "n2", TrustLabel.TRUSTED),
    ]
    rs = reconcile("sub", reports, nodes, topo, at=_t0())
    assert rs.visibility_gap is True


def test_reconcile_defensibility_lower_under_split_brain() -> None:
    topo_ok = _topology_single("n1", "n2")
    topo_split = _topology_split(("n1",), ("n2",))
    nodes = {"n1": _node("n1", trust=0.9), "n2": _node("n2", trust=0.9)}
    reports = [
        _report("r1", "sub", "n1", TrustLabel.TRUSTED),
        _report("r2", "sub", "n2", TrustLabel.TRUSTED),
    ]
    d_ok = reconcile("sub", reports, nodes, topo_ok, at=_t0()).defensibility
    d_split = reconcile("sub", reports, nodes, topo_split, at=_t0()).defensibility
    assert d_split < d_ok


# ---- transitions ----------------------------------------------------------

def test_transition_compromise_to_trusted_rejected() -> None:
    d = evaluate_transition(TransitionRequest(
        subject_id="s", from_label=TrustLabel.COMPROMISED,
        to_label=TrustLabel.TRUSTED, reason="x", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


def test_transition_quarantine_recovery_requires_verification() -> None:
    d = evaluate_transition(TransitionRequest(
        subject_id="s", from_label=TrustLabel.QUARANTINED,
        to_label=TrustLabel.OBSERVED, reason="x", verified=False,
    ))
    assert d.outcome is TransitionOutcome.REQUIRES_VERIFICATION


def test_transition_reason_required() -> None:
    d = evaluate_transition(TransitionRequest(
        subject_id="s", from_label=TrustLabel.OBSERVED,
        to_label=TrustLabel.TRUSTED, reason="", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


# ---- engine integration ---------------------------------------------------

def test_engine_registers_and_reconciles() -> None:
    eng = DistributedSecurityStateEngine()
    for n in ("n1", "n2", "n3"):
        eng.register_node(_node(n))
    eng.add_partition(PartitionView("p1", frozenset({"n1", "n2", "n3"})))
    eng.report(_report("r1", "sub", "n1", TrustLabel.TRUSTED))
    eng.report(_report("r2", "sub", "n2", TrustLabel.TRUSTED))
    eng.report(_report("r3", "sub", "n3", TrustLabel.TRUSTED))
    records = eng.recompute(at=_t0())
    rec = next(r for r in records if r.subject_id == "sub")
    assert rec.label is TrustLabel.TRUSTED


def test_engine_unknown_source_rejected() -> None:
    eng = DistributedSecurityStateEngine()
    try:
        eng.report(_report("r1", "sub", "ghost", TrustLabel.TRUSTED))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_partition_member_must_be_registered() -> None:
    eng = DistributedSecurityStateEngine()
    eng.register_node(_node("n1"))
    try:
        eng.add_partition(PartitionView("p1", frozenset({"n1", "ghost"})))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_invariant_trusted_no_quorum() -> None:
    # reconcile() now prevents TRUSTED off a single source outright (see
    # the corroboration check added in reconcile()), so this state can no
    # longer arise through the normal flow. Inject it directly to confirm
    # the detective invariant still catches it as defense-in-depth.
    eng = DistributedSecurityStateEngine()
    eng.register_node(_node("n1", trust=0.95))
    eng.add_partition(PartitionView("p1", frozenset({"n1"})))
    t = _t0()
    fake = ReconciledState(
        subject_id="sub", label=TrustLabel.TRUSTED, defensibility=0.9,
        divergence=DivergenceResult(
            kind=DivergenceKind.AGREE, label_weights={TrustLabel.TRUSTED: 0.95},
            total_weight=0.95, winning_label=TrustLabel.TRUSTED,
            winning_share=1.0, divergence=0.0, distinct_labels=1,
        ),
        supporting_weight=0.95, used_report_ids=("r1",),
        dropped_report_ids=(), split_brain=False, visibility_gap=False,
        adversarial_signal=False, rationale="injected for invariant test",
        at=t,
    )
    eng._reconciliations["sub"] = fake
    assert any(v.invariant_id == "dist.no_trusted_without_quorum"
               for v in eng.violations())


def test_engine_invariant_split_brain_not_trusted() -> None:
    eng = DistributedSecurityStateEngine()
    for n in ("n1", "n2", "n3", "n4"):
        eng.register_node(_node(n, trust=0.95))
    eng.add_partition(PartitionView("pa", frozenset({"n1", "n2"})))
    eng.add_partition(PartitionView("pb", frozenset({"n3", "n4"})))
    eng.set_partition_link("pa", "pb", False)
    eng.set_partition_link("pb", "pa", False)
    eng.report(_report("r1", "sub", "n1", TrustLabel.TRUSTED))
    eng.report(_report("r2", "sub", "n2", TrustLabel.TRUSTED))
    eng.report(_report("r3", "sub", "n3", TrustLabel.TRUSTED))
    eng.report(_report("r4", "sub", "n4", TrustLabel.TRUSTED))
    eng.recompute(at=_t0())
    # split brain → must not be TRUSTED (invariant violated if it is)
    rs = eng.reconciliation("sub")
    assert rs is not None
    assert rs.split_brain
    # label must not be TRUSTED
    assert rs.label is not TrustLabel.TRUSTED


def test_engine_invariant_adversarial_signal_not_silent() -> None:
    eng = DistributedSecurityStateEngine()
    for n in ("n1", "n2", "n3"):
        eng.register_node(_node(n, trust=0.95))
    eng.add_partition(PartitionView("p1", frozenset({"n1", "n2", "n3"})))
    eng.report(_report("r1", "sub", "n1", TrustLabel.TRUSTED))
    eng.report(_report("r2", "sub", "n2", TrustLabel.TRUSTED))
    eng.report(_report("r3", "sub", "n3", TrustLabel.COMPROMISED))
    records = eng.recompute(at=_t0())
    rec = next(r for r in records if r.subject_id == "sub")
    assert rec.adversarial_signal is True
    assert label_severity(rec.label) >= label_severity(TrustLabel.SUSPICIOUS)


def test_engine_quarantined_source_dropped() -> None:
    eng = DistributedSecurityStateEngine()
    eng.register_node(_node("n1", trust=0.95))
    eng.register_node(_node("n2", trust=0.95, quarantined=True))
    eng.add_partition(PartitionView("p1", frozenset({"n1", "n2"})))
    eng.report(_report("r1", "sub", "n1", TrustLabel.TRUSTED))
    eng.report(_report("r2", "sub", "n2", TrustLabel.TRUSTED))
    rs = eng.recompute(at=_t0())
    recon = eng.reconciliation("sub")
    assert recon is not None
    assert "r2" in recon.dropped_report_ids


# ---- store tests ----------------------------------------------------------

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryDistributedStore()
    t = _t0()
    s.put(ReconciledRecord("sub", TrustLabel.TRUSTED, 0.9, False, False, False, t))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(ReconciledRecord("sub", TrustLabel.UNKNOWN, 0.5, False, False, False, earlier))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_reconciled_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "dist.db")
    store = SqliteDistributedStore(db)
    t = _t0()
    store.put(ReconciledRecord(
        "sub", TrustLabel.SUSPICIOUS, 0.7, True, False, True, t,
    ))
    got = store.get("sub")
    assert got is not None
    assert got.label is TrustLabel.SUSPICIOUS
    assert got.split_brain is True
    assert got.adversarial_signal is True


def test_sqlite_store_report_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "dist.db")
    store = SqliteDistributedStore(db)
    rep = _report("r1", "sub", "n1", TrustLabel.TRUSTED)
    store.put_report(rep)
    got = store.get_report("r1")
    assert got is not None
    assert got.label is TrustLabel.TRUSTED
    assert got.subject_id == "sub"


# ---- policy validation ----------------------------------------------------

def test_policy_requires_positive_half_life() -> None:
    try:
        ReconciliationPolicy(half_life_seconds=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_policy_requires_positive_max_age() -> None:
    try:
        ReconciliationPolicy(max_age_seconds=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_policy_min_source_trust_bounds() -> None:
    try:
        ReconciliationPolicy(min_source_trust=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_policy_split_brain_min_partitions() -> None:
    try:
        ReconciliationPolicy(split_brain_min_partitions=1)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


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
