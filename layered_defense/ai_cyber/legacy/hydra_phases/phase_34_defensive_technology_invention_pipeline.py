"""
HYDRA POST-CORE — PHASE 34: DEFENSIVE TECHNOLOGY INVENTION PIPELINE
======================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 9 pipeline stages, 5 problem severities, 4 novelty
    classes, 4 feasibility classes, 4 verification outcomes,
    4 promotion verdicts, 11 finding kinds
  * Controlled invention pipeline:

        PROBLEM
          ↓
        CURRENT DEFENSE
          ↓
        DEFENSE LIMITATION
          ↓
        MISSING CAPABILITY
          ↓
        CANDIDATE TECHNOLOGY
          ↓
        SIMULATION
          ↓
        ADVERSARIAL TEST
          ↓
        VERIFICATION
          ↓
        PROMOTE / REJECT

  * Every stage carries explicit evidence. A candidate cannot be
    promoted unless every gate passes:
      - feasibility ≥ MIN_FEASIBILITY
      - novelty ≥ MIN_NOVELTY
      - measurable value ≥ MIN_VALUE
      - security analysis passes (no regressions)
      - simulation passes with success ≥ MIN_SUCCESS
      - adversarial testing survives ≥ MIN_ADVERSARIAL_MARGIN
      - verification outcome is PASSED (or STRONG_PASS)
      - no invariant violations

  * Findings — 11 kinds
  * Machine-checkable invention invariants
  * In-memory + SQLite stores
  * Phase-34 engine facade
  * Full test suite + manual runner

Doctrine: the system must NOT blindly invent. Every candidate must
pass every gate; any failure yields REJECT or HOLD with an explicit
reason. Every promotion carries full provenance from PROBLEM to
VERIFICATION.

No third-party dependencies.

Run tests:
    python hydra_phase34_defensive_invention_pipeline.py
    pytest hydra_phase34_defensive_invention_pipeline.py -q
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
# SECTION 2 — DOMAIN ENUMS
# =============================================================================


class PipelineStage(str, Enum):
    PROBLEM = "problem"
    CURRENT_DEFENSE = "current_defense"
    DEFENSE_LIMITATION = "defense_limitation"
    MISSING_CAPABILITY = "missing_capability"
    CANDIDATE_TECHNOLOGY = "candidate_technology"
    SIMULATION = "simulation"
    ADVERSARIAL_TEST = "adversarial_test"
    VERIFICATION = "verification"
    PROMOTION = "promotion"


PIPELINE_ORDER: Tuple[PipelineStage, ...] = (
    PipelineStage.PROBLEM,
    PipelineStage.CURRENT_DEFENSE,
    PipelineStage.DEFENSE_LIMITATION,
    PipelineStage.MISSING_CAPABILITY,
    PipelineStage.CANDIDATE_TECHNOLOGY,
    PipelineStage.SIMULATION,
    PipelineStage.ADVERSARIAL_TEST,
    PipelineStage.VERIFICATION,
    PipelineStage.PROMOTION,
)


def stage_index(s: PipelineStage) -> int:
    return PIPELINE_ORDER.index(s)


class ProblemSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_WEIGHT: Mapping[ProblemSeverity, int] = {
    ProblemSeverity.LOW: 1,
    ProblemSeverity.MEDIUM: 2,
    ProblemSeverity.HIGH: 3,
    ProblemSeverity.CRITICAL: 4,
}


def severity_weight(s: ProblemSeverity) -> int:
    return _SEVERITY_WEIGHT[s]


class FeasibilityClass(str, Enum):
    INFEASIBLE = "infeasible"
    UNCERTAIN = "uncertain"
    FEASIBLE = "feasible"
    STRONGLY_FEASIBLE = "strongly_feasible"


_FEASIBILITY_RANK: Mapping[FeasibilityClass, int] = {
    FeasibilityClass.INFEASIBLE: 0,
    FeasibilityClass.UNCERTAIN: 1,
    FeasibilityClass.FEASIBLE: 2,
    FeasibilityClass.STRONGLY_FEASIBLE: 3,
}


def feasibility_rank(f: FeasibilityClass) -> int:
    return _FEASIBILITY_RANK[f]


class NoveltyClass(str, Enum):
    DUPLICATE = "duplicate"
    MARGINAL = "marginal"
    NOVEL = "novel"
    NOVEL_INVENTION = "novel_invention"


_NOVELTY_RANK: Mapping[NoveltyClass, int] = {
    NoveltyClass.DUPLICATE: 0,
    NoveltyClass.MARGINAL: 1,
    NoveltyClass.NOVEL: 2,
    NoveltyClass.NOVEL_INVENTION: 3,
}


def novelty_rank(n: NoveltyClass) -> int:
    return _NOVELTY_RANK[n]


class VerificationOutcome(str, Enum):
    FAILED = "failed"
    WEAK_PASS = "weak_pass"
    PASSED = "passed"
    STRONG_PASS = "strong_pass"


_VERIFICATION_RANK: Mapping[VerificationOutcome, int] = {
    VerificationOutcome.FAILED: 0,
    VerificationOutcome.WEAK_PASS: 1,
    VerificationOutcome.PASSED: 2,
    VerificationOutcome.STRONG_PASS: 3,
}


def verification_rank(v: VerificationOutcome) -> int:
    return _VERIFICATION_RANK[v]


class PromotionVerdict(str, Enum):
    PROMOTE = "promote"
    HOLD = "hold"
    REJECT = "reject"


class FindingKind(str, Enum):
    NO_DEFENSE_EXISTS = "no_defense_exists"
    DEFENSE_INSUFFICIENT = "defense_insufficient"
    MISSING_CAPABILITY_IDENTIFIED = "missing_capability_identified"
    CANDIDATE_PROPOSED = "candidate_proposed"
    CANDIDATE_DUPLICATE = "candidate_duplicate"
    CANDIDATE_LOW_VALUE = "candidate_low_value"
    SIMULATION_FAILED = "simulation_failed"
    ADVERSARIAL_SURVIVAL_LOW = "adversarial_survival_low"
    VERIFICATION_FAILED = "verification_failed"
    PROMOTED = "promoted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class InventionFinding:
    kind: FindingKind
    subject_id: str
    detail: str
    severity: int
    stage: PipelineStage
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 1 <= self.severity <= 5:
            raise ValueError("severity must be in [1,5]")


# =============================================================================
# SECTION 3 — STAGE 1: PROBLEM
# =============================================================================


@dataclass(frozen=True)
class Problem:
    problem_id: str
    title: str
    description: str
    severity: ProblemSeverity
    domain: str
    detected_at: datetime
    evidence_refs: Tuple[str, ...] = ()
    tags: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.problem_id:
            raise ValueError("problem_id is required")
        if not self.title:
            raise ValueError("title is required")
        if not self.description:
            raise ValueError("description is required")
        if not self.domain:
            raise ValueError("domain is required")
        if self.detected_at.tzinfo is None:
            raise ValueError("detected_at must be timezone-aware")


# =============================================================================
# SECTION 4 — STAGE 2: CURRENT DEFENSE
# =============================================================================


@dataclass(frozen=True)
class CurrentDefense:
    defense_id: str
    problem_id: str
    name: str
    description: str
    coverage: float           # 0..1 — how much of the problem it covers
    confidence: float         # 0..1 — how sure we are about coverage
    limitations: Tuple[str, ...] = ()
    degraded_by: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.defense_id:
            raise ValueError("defense_id is required")
        if not self.problem_id:
            raise ValueError("problem_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not 0.0 <= self.coverage <= 1.0:
            raise ValueError("coverage must be within [0,1]")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")


# =============================================================================
# SECTION 5 — STAGE 3: DEFENSE LIMITATION
# =============================================================================


@dataclass(frozen=True)
class DefenseLimitation:
    limitation_id: str
    problem_id: str
    defense_id: Optional[str]     # None means "no defense exists"
    description: str
    severity: ProblemSeverity
    gap_score: float              # 0..1 — how big the residual gap is
    detected_at: datetime

    def __post_init__(self) -> None:
        if not self.limitation_id:
            raise ValueError("limitation_id is required")
        if not self.problem_id:
            raise ValueError("problem_id is required")
        if not self.description:
            raise ValueError("description is required")
        if not 0.0 <= self.gap_score <= 1.0:
            raise ValueError("gap_score must be within [0,1]")
        if self.detected_at.tzinfo is None:
            raise ValueError("detected_at must be timezone-aware")


# =============================================================================
# SECTION 6 — STAGE 4: MISSING CAPABILITY
# =============================================================================


@dataclass(frozen=True)
class MissingCapability:
    capability_id: str
    problem_id: str
    limitation_id: str
    name: str
    description: str
    required_properties: FrozenSet[str]
    must_be_independent: bool = True
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.capability_id:
            raise ValueError("capability_id is required")
        if not self.problem_id:
            raise ValueError("problem_id is required")
        if not self.limitation_id:
            raise ValueError("limitation_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not self.required_properties:
            raise ValueError("required_properties must be non-empty")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 7 — STAGE 5: CANDIDATE TECHNOLOGY
# =============================================================================


@dataclass(frozen=True)
class CandidateTechnology:
    candidate_id: str
    problem_id: str
    capability_id: str
    name: str
    description: str
    approach: str
    feasibility: FeasibilityClass
    novelty: NoveltyClass
    measurable_value: float       # 0..1 — how much value it claims to add
    security_analysis_passed: bool
    security_regressions: Tuple[str, ...] = ()
    overlaps_existing: Tuple[str, ...] = ()
    required_properties: FrozenSet[str] = frozenset()
    proposed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise ValueError("candidate_id is required")
        if not self.problem_id:
            raise ValueError("problem_id is required")
        if not self.capability_id:
            raise ValueError("capability_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not self.description:
            raise ValueError("description is required")
        if not self.approach:
            raise ValueError("approach is required")
        if not 0.0 <= self.measurable_value <= 1.0:
            raise ValueError("measurable_value must be within [0,1]")
        if self.proposed_at is not None and self.proposed_at.tzinfo is None:
            raise ValueError("proposed_at must be timezone-aware")


# =============================================================================
# SECTION 8 — STAGE 6: SIMULATION
# =============================================================================


@dataclass(frozen=True)
class SimulationResult:
    simulation_id: str
    candidate_id: str
    scenarios_run: int
    scenarios_passed: int
    success_rate: float           # 0..1
    side_effect_score: float      # 0..1 — smaller is better
    performance_overhead: float   # 0..1
    notes: Tuple[str, ...] = ()
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.simulation_id:
            raise ValueError("simulation_id is required")
        if not self.candidate_id:
            raise ValueError("candidate_id is required")
        if self.scenarios_run < 0:
            raise ValueError("scenarios_run must be >= 0")
        if self.scenarios_passed < 0:
            raise ValueError("scenarios_passed must be >= 0")
        if self.scenarios_passed > self.scenarios_run:
            raise ValueError("passed cannot exceed run")
        for n, v in (
            ("success_rate", self.success_rate),
            ("side_effect_score", self.side_effect_score),
            ("performance_overhead", self.performance_overhead),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 9 — STAGE 7: ADVERSARIAL TEST
# =============================================================================


@dataclass(frozen=True)
class AdversarialTestResult:
    test_id: str
    candidate_id: str
    attacks_attempted: int
    attacks_survived: int
    survival_rate: float          # 0..1
    worst_case_loss: float        # 0..1
    failure_modes: Tuple[str, ...] = ()
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.test_id:
            raise ValueError("test_id is required")
        if not self.candidate_id:
            raise ValueError("candidate_id is required")
        if self.attacks_attempted < 0:
            raise ValueError("attacks_attempted must be >= 0")
        if self.attacks_survived < 0:
            raise ValueError("attacks_survived must be >= 0")
        if self.attacks_survived > self.attacks_attempted:
            raise ValueError("survived cannot exceed attempted")
        for n, v in (
            ("survival_rate", self.survival_rate),
            ("worst_case_loss", self.worst_case_loss),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 10 — STAGE 8: VERIFICATION
# =============================================================================


@dataclass(frozen=True)
class VerificationResult:
    verification_id: str
    candidate_id: str
    outcome: VerificationOutcome
    independent_verifiers: Tuple[str, ...]
    evidence: Tuple[str, ...]
    residual_uncertainty: float   # 0..1
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.verification_id:
            raise ValueError("verification_id is required")
        if not self.candidate_id:
            raise ValueError("candidate_id is required")
        if not 0.0 <= self.residual_uncertainty <= 1.0:
            raise ValueError("residual_uncertainty must be within [0,1]")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 11 — PROMOTION DECISION
# =============================================================================


@dataclass(frozen=True)
class PromotionDecision:
    decision_id: str
    candidate_id: str
    problem_id: str
    verdict: PromotionVerdict
    rationale: str
    stage_reached: PipelineStage
    failing_gates: Tuple[str, ...]
    evidence_chain: Tuple[str, ...]
    at: datetime

    def __post_init__(self) -> None:
        if not self.decision_id:
            raise ValueError("decision_id is required")
        if not self.candidate_id:
            raise ValueError("candidate_id is required")
        if not self.problem_id:
            raise ValueError("problem_id is required")
        if not self.rationale:
            raise ValueError("rationale is required")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class PromotionGates:
    min_feasibility: FeasibilityClass = FeasibilityClass.FEASIBLE
    min_novelty: NoveltyClass = NoveltyClass.NOVEL
    min_value: float = 0.3
    min_simulation_success: float = 0.6
    max_side_effect_score: float = 0.4
    max_performance_overhead: float = 0.4
    min_adversarial_survival: float = 0.7
    min_adversarial_attacks: int = 10
    max_worst_case_loss: float = 0.3
    min_verification: VerificationOutcome = VerificationOutcome.PASSED
    min_independent_verifiers: int = 1
    max_residual_uncertainty: float = 0.3

    def __post_init__(self) -> None:
        for n, v in (
            ("min_value", self.min_value),
            ("min_simulation_success", self.min_simulation_success),
            ("max_side_effect_score", self.max_side_effect_score),
            ("max_performance_overhead", self.max_performance_overhead),
            ("min_adversarial_survival", self.min_adversarial_survival),
            ("max_worst_case_loss", self.max_worst_case_loss),
            ("max_residual_uncertainty", self.max_residual_uncertainty),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.min_independent_verifiers < 1:
            raise ValueError("min_independent_verifiers must be >= 1")
        if self.min_adversarial_attacks < 1:
            raise ValueError("min_adversarial_attacks must be >= 1")


# =============================================================================
# SECTION 12 — INVARIANTS
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
class InventionSnapshot:
    problems: Mapping[str, Problem]
    defenses: Mapping[str, CurrentDefense]
    limitations: Mapping[str, DefenseLimitation]
    capabilities: Mapping[str, MissingCapability]
    candidates: Mapping[str, CandidateTechnology]
    simulations: Mapping[str, SimulationResult]
    adversarial_tests: Mapping[str, AdversarialTestResult]
    verifications: Mapping[str, VerificationResult]
    decisions: Mapping[str, PromotionDecision]
    findings: Tuple[InventionFinding, ...]


@dataclass(frozen=True)
class InventionInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[InventionSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_promotions_have_full_provenance(
    snap: InventionSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, d in snap.decisions.items():
        if d.verdict is not PromotionVerdict.PROMOTE:
            continue
        # must reach PROMOTION stage
        if d.stage_reached is not PipelineStage.PROMOTION:
            out.append(InvariantViolation(
                invariant_id="inv.promotion_requires_full_provenance",
                severity=InvariantSeverity.CRITICAL,
                subject_id=did,
                detail=(
                    f"promotion without reaching PROMOTION stage "
                    f"(reached {d.stage_reached.value})"
                ),
            ))
        # must have full evidence chain (problem + capability + candidate
        # + simulation + adversarial + verification - see
        # test_engine_promotion_evidence_chain_full for why this is 6,
        # not len(PIPELINE_ORDER) - 1: current-defense/limitation stages
        # never contribute their own evidence-chain entry)
        if len(d.evidence_chain) < 6:
            out.append(InvariantViolation(
                invariant_id="inv.promotion_requires_full_provenance",
                severity=InvariantSeverity.CRITICAL,
                subject_id=did,
                detail=(
                    f"evidence chain has {len(d.evidence_chain)} "
                    f"entries, expected ≥ 6"
                ),
            ))
        # must have no failing gates
        if d.failing_gates:
            out.append(InvariantViolation(
                invariant_id="inv.promotion_requires_full_provenance",
                severity=InvariantSeverity.CRITICAL,
                subject_id=did,
                detail=(
                    f"promotion with failing gates: "
                    f"{list(d.failing_gates)}"
                ),
            ))
    return tuple(out)


def _inv_no_promote_without_verification(
    snap: InventionSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, d in snap.decisions.items():
        if d.verdict is not PromotionVerdict.PROMOTE:
            continue
        v = snap.verifications.get(d.candidate_id)
        if v is None:
            out.append(InvariantViolation(
                invariant_id="inv.promote_requires_verification",
                severity=InvariantSeverity.CRITICAL,
                subject_id=did,
                detail="promotion without verification record",
            ))
    return tuple(out)


def _inv_no_promote_without_adversarial(
    snap: InventionSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, d in snap.decisions.items():
        if d.verdict is not PromotionVerdict.PROMOTE:
            continue
        a = snap.adversarial_tests.get(d.candidate_id)
        if a is None:
            out.append(InvariantViolation(
                invariant_id="inv.promote_requires_adversarial",
                severity=InvariantSeverity.CRITICAL,
                subject_id=did,
                detail="promotion without adversarial test record",
            ))
    return tuple(out)


def _inv_no_promote_without_simulation(
    snap: InventionSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, d in snap.decisions.items():
        if d.verdict is not PromotionVerdict.PROMOTE:
            continue
        s = snap.simulations.get(d.candidate_id)
        if s is None:
            out.append(InvariantViolation(
                invariant_id="inv.promote_requires_simulation",
                severity=InvariantSeverity.CRITICAL,
                subject_id=did,
                detail="promotion without simulation record",
            ))
    return tuple(out)


def _inv_no_promote_duplicate(
    snap: InventionSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, d in snap.decisions.items():
        if d.verdict is not PromotionVerdict.PROMOTE:
            continue
        c = snap.candidates.get(d.candidate_id)
        if c is None:
            continue
        if c.novelty is NoveltyClass.DUPLICATE:
            out.append(InvariantViolation(
                invariant_id="inv.promote_not_duplicate",
                severity=InvariantSeverity.CRITICAL,
                subject_id=did,
                detail="promoted a DUPLICATE novelty candidate",
            ))
    return tuple(out)


def _inv_evidence_chain_refs_registered(
    snap: InventionSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for did, d in snap.decisions.items():
        for ref in d.evidence_chain:
            # Refs are opaque ids. We only check they're non-empty.
            if not ref:
                out.append(InvariantViolation(
                    invariant_id="inv.evidence_chain_nonempty",
                    severity=InvariantSeverity.HIGH,
                    subject_id=did,
                    detail="empty evidence-chain reference",
                ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[InventionInvariant, ...] = (
    InventionInvariant(
        invariant_id="inv.promotion_requires_full_provenance",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_promotions_have_full_provenance,
        description="Promotions require full provenance chain.",
    ),
    InventionInvariant(
        invariant_id="inv.promote_requires_verification",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_promote_without_verification,
        description="Promotions require a verification record.",
    ),
    InventionInvariant(
        invariant_id="inv.promote_requires_adversarial",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_promote_without_adversarial,
        description="Promotions require an adversarial test record.",
    ),
    InventionInvariant(
        invariant_id="inv.promote_requires_simulation",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_promote_without_simulation,
        description="Promotions require a simulation record.",
    ),
    InventionInvariant(
        invariant_id="inv.promote_not_duplicate",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_promote_duplicate,
        description="Duplicates must not be promoted.",
    ),
    InventionInvariant(
        invariant_id="inv.evidence_chain_nonempty",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_evidence_chain_refs_registered,
        description="Evidence chain references must be non-empty.",
    ),
)


def check_invariants(
    snap: InventionSnapshot,
    invariants: Iterable[InventionInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 13 — STORE
# =============================================================================


@dataclass(frozen=True)
class CandidateRecord:
    candidate_id: str
    problem_id: str
    name: str
    feasibility: FeasibilityClass
    novelty: NoveltyClass
    measurable_value: float
    stage_reached: PipelineStage
    verdict: Optional[PromotionVerdict]
    updated_at: datetime


class InventionStore(Protocol):
    def put(self, record: CandidateRecord) -> None: ...
    def get(self, candidate_id: str) -> Optional[CandidateRecord]: ...
    def all(self) -> Tuple[CandidateRecord, ...]: ...


class InMemoryInventionStore:
    def __init__(self) -> None:
        self._data: Dict[str, CandidateRecord] = {}

    def put(self, record: CandidateRecord) -> None:
        existing = self._data.get(record.candidate_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.candidate_id] = record

    def get(self, candidate_id: str) -> Optional[CandidateRecord]:
        return self._data.get(candidate_id)

    def all(self) -> Tuple[CandidateRecord, ...]:
        return tuple(self._data.values())


class SqliteInventionStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS invention_candidates (
                candidate_id TEXT PRIMARY KEY,
                problem_id TEXT NOT NULL,
                name TEXT NOT NULL,
                feasibility TEXT NOT NULL,
                novelty TEXT NOT NULL,
                measurable_value REAL NOT NULL,
                stage_reached TEXT NOT NULL,
                verdict TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS invention_decisions (
                decision_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: CandidateRecord) -> None:
        existing = self.get(record.candidate_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO invention_candidates
              (candidate_id, problem_id, name, feasibility, novelty,
               measurable_value, stage_reached, verdict, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(candidate_id) DO UPDATE SET
              problem_id=excluded.problem_id,
              name=excluded.name,
              feasibility=excluded.feasibility,
              novelty=excluded.novelty,
              measurable_value=excluded.measurable_value,
              stage_reached=excluded.stage_reached,
              verdict=excluded.verdict,
              updated_at=excluded.updated_at
            """,
            (
                record.candidate_id, record.problem_id, record.name,
                record.feasibility.value, record.novelty.value,
                record.measurable_value, record.stage_reached.value,
                record.verdict.value if record.verdict else None,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, candidate_id: str) -> Optional[CandidateRecord]:
        row = self._conn.execute(
            "SELECT problem_id, name, feasibility, novelty, "
            "measurable_value, stage_reached, verdict, updated_at "
            "FROM invention_candidates WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        if row is None:
            return None
        return CandidateRecord(
            candidate_id=candidate_id, problem_id=row[0], name=row[1],
            feasibility=FeasibilityClass(row[2]),
            novelty=NoveltyClass(row[3]),
            measurable_value=float(row[4]),
            stage_reached=PipelineStage(row[5]),
            verdict=PromotionVerdict(row[6]) if row[6] else None,
            updated_at=datetime.fromisoformat(row[7]),
        )

    def all(self) -> Tuple[CandidateRecord, ...]:
        rows = self._conn.execute(
            "SELECT candidate_id FROM invention_candidates"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_decision(self, decision_id: str, d: PromotionDecision) -> None:
        payload = {
            "decision_id": decision_id,
            "candidate_id": d.candidate_id,
            "problem_id": d.problem_id,
            "verdict": d.verdict.value,
            "rationale": d.rationale,
            "stage_reached": d.stage_reached.value,
            "failing_gates": list(d.failing_gates),
            "evidence_chain": list(d.evidence_chain),
            "at": d.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO invention_decisions "
            "(decision_id, payload_json) VALUES (?, ?)",
            (decision_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 14 — ENGINE
# =============================================================================


class DefensiveInventionEngine:
    """Controlled defensive-technology invention pipeline.

    Every candidate must pass every gate before PROMOTE. Any failure
    yields HOLD or REJECT with an explicit failing-gate list.
    """

    def __init__(
        self,
        *,
        store: Optional[InventionStore] = None,
        gates: Optional[PromotionGates] = None,
        max_candidates: int = 2000,
    ) -> None:
        if max_candidates < 1:
            raise ValueError("max_candidates must be >= 1")
        self._store: InventionStore = store or InMemoryInventionStore()
        self._gates = gates or PromotionGates()
        self._max_candidates = max_candidates

        self._problems: Dict[str, Problem] = {}
        self._defenses: Dict[str, CurrentDefense] = {}
        self._limitations: Dict[str, DefenseLimitation] = {}
        self._capabilities: Dict[str, MissingCapability] = {}
        self._candidates: Dict[str, CandidateTechnology] = {}
        self._simulations: Dict[str, SimulationResult] = {}
        self._adversarial: Dict[str, AdversarialTestResult] = {}
        self._verifications: Dict[str, VerificationResult] = {}
        self._decisions: Dict[str, PromotionDecision] = {}
        self._findings: List[InventionFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._decision_seq: int = 0

    # ---- config ----------------------------------------------------------

    def gates(self) -> PromotionGates:
        return self._gates

    def set_gates(self, gates: PromotionGates) -> None:
        self._gates = gates

    # ---- registration ----------------------------------------------------

    def register_problem(self, problem: Problem) -> None:
        if problem.problem_id in self._problems:
            raise ValueError(
                f"problem {problem.problem_id} already registered"
            )
        self._problems[problem.problem_id] = problem

    def register_defense(self, defense: CurrentDefense) -> None:
        if defense.problem_id not in self._problems:
            raise KeyError(
                f"problem {defense.problem_id} not registered"
            )
        if defense.defense_id in self._defenses:
            raise ValueError(
                f"defense {defense.defense_id} already registered"
            )
        self._defenses[defense.defense_id] = defense

    def register_limitation(self, lim: DefenseLimitation) -> None:
        if lim.problem_id not in self._problems:
            raise KeyError(f"problem {lim.problem_id} not registered")
        if lim.defense_id is not None \
           and lim.defense_id not in self._defenses:
            raise KeyError(f"defense {lim.defense_id} not registered")
        if lim.limitation_id in self._limitations:
            raise ValueError(
                f"limitation {lim.limitation_id} already registered"
            )
        self._limitations[lim.limitation_id] = lim

    def register_capability(self, cap: MissingCapability) -> None:
        if cap.problem_id not in self._problems:
            raise KeyError(f"problem {cap.problem_id} not registered")
        if cap.limitation_id not in self._limitations:
            raise KeyError(
                f"limitation {cap.limitation_id} not registered"
            )
        if cap.capability_id in self._capabilities:
            raise ValueError(
                f"capability {cap.capability_id} already registered"
            )
        self._capabilities[cap.capability_id] = cap

    def register_candidate(self, cand: CandidateTechnology) -> None:
        if cand.problem_id not in self._problems:
            raise KeyError(f"problem {cand.problem_id} not registered")
        if cand.capability_id not in self._capabilities:
            raise KeyError(
                f"capability {cand.capability_id} not registered"
            )
        if cand.candidate_id in self._candidates:
            raise ValueError(
                f"candidate {cand.candidate_id} already registered"
            )
        if len(self._candidates) >= self._max_candidates:
            raise ValueError(
                f"candidate count exceeds max {self._max_candidates}"
            )
        self._candidates[cand.candidate_id] = cand

    def record_simulation(self, sim: SimulationResult) -> None:
        if sim.candidate_id not in self._candidates:
            raise KeyError(
                f"candidate {sim.candidate_id} not registered"
            )
        if sim.candidate_id in self._simulations:
            raise ValueError(
                f"candidate {sim.candidate_id} already simulated"
            )
        self._simulations[sim.candidate_id] = sim

    def record_adversarial(self, at: AdversarialTestResult) -> None:
        if at.candidate_id not in self._candidates:
            raise KeyError(
                f"candidate {at.candidate_id} not registered"
            )
        if at.candidate_id in self._adversarial:
            raise ValueError(
                f"candidate {at.candidate_id} already adversarial-tested"
            )
        self._adversarial[at.candidate_id] = at

    def record_verification(self, v: VerificationResult) -> None:
        if v.candidate_id not in self._candidates:
            raise KeyError(
                f"candidate {v.candidate_id} not registered"
            )
        if v.candidate_id in self._verifications:
            raise ValueError(
                f"candidate {v.candidate_id} already verified"
            )
        self._verifications[v.candidate_id] = v

    # ---- queries ---------------------------------------------------------

    def problem(self, problem_id: str) -> Optional[Problem]:
        return self._problems.get(problem_id)

    def candidate(self, cid: str) -> Optional[CandidateTechnology]:
        return self._candidates.get(cid)

    def decision(self, decision_id: str) -> Optional[PromotionDecision]:
        return self._decisions.get(decision_id)

    def simulation(self, cid: str) -> Optional[SimulationResult]:
        return self._simulations.get(cid)

    def adversarial(self, cid: str) -> Optional[AdversarialTestResult]:
        return self._adversarial.get(cid)

    def verification(self, cid: str) -> Optional[VerificationResult]:
        return self._verifications.get(cid)

    # ---- decision --------------------------------------------------------

    def evaluate_candidate(
        self,
        candidate_id: str,
        *,
        at: datetime,
    ) -> PromotionDecision:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        cand = self._candidates.get(candidate_id)
        if cand is None:
            raise KeyError(f"candidate {candidate_id} not registered")

        gates = self._gates
        failing: List[str] = []
        reached = PipelineStage.CANDIDATE_TECHNOLOGY
        evidence_chain: List[str] = [
            cand.problem_id, cand.capability_id, cand.candidate_id,
        ]

        # Stage 5 gates — feasibility, novelty, value, security analysis
        if feasibility_rank(cand.feasibility) < \
                feasibility_rank(gates.min_feasibility):
            failing.append("feasibility")
        if novelty_rank(cand.novelty) < novelty_rank(gates.min_novelty):
            failing.append("novelty")
        if cand.measurable_value < gates.min_value:
            failing.append("measurable_value")
        if not cand.security_analysis_passed:
            failing.append("security_analysis")
        if cand.security_regressions:
            failing.append("security_regressions")

        # Stage 6 — simulation
        sim = self._simulations.get(candidate_id)
        if sim is None:
            failing.append("simulation_missing")
        else:
            reached = PipelineStage.SIMULATION
            evidence_chain.append(sim.simulation_id)
            if sim.success_rate < gates.min_simulation_success:
                failing.append("simulation_success")
            if sim.side_effect_score > gates.max_side_effect_score:
                failing.append("simulation_side_effects")
            if sim.performance_overhead > gates.max_performance_overhead:
                failing.append("simulation_overhead")

        # Stage 7 — adversarial
        adv = self._adversarial.get(candidate_id)
        if adv is None:
            failing.append("adversarial_missing")
        else:
            reached = PipelineStage.ADVERSARIAL_TEST
            evidence_chain.append(adv.test_id)
            if adv.attacks_attempted < gates.min_adversarial_attacks:
                failing.append("adversarial_attack_count")
            if adv.survival_rate < gates.min_adversarial_survival:
                failing.append("adversarial_survival")
            if adv.worst_case_loss > gates.max_worst_case_loss:
                failing.append("adversarial_worst_case")

        # Stage 8 — verification
        ver = self._verifications.get(candidate_id)
        if ver is None:
            failing.append("verification_missing")
        else:
            reached = PipelineStage.VERIFICATION
            evidence_chain.append(ver.verification_id)
            if verification_rank(ver.outcome) < \
                    verification_rank(gates.min_verification):
                failing.append("verification_outcome")
            if len(ver.independent_verifiers) < \
                    gates.min_independent_verifiers:
                failing.append("verification_independents")
            if ver.residual_uncertainty > gates.max_residual_uncertainty:
                failing.append("verification_uncertainty")

        # Duplicate check
        if cand.novelty is NoveltyClass.DUPLICATE:
            failing.append("duplicate")

        # Verdict
        if not failing:
            verdict = PromotionVerdict.PROMOTE
            reached = PipelineStage.PROMOTION
            rationale = (
                f"all gates passed for {candidate_id} "
                f"({cand.name})"
            )
        else:
            # Distinguish HOLD vs REJECT: REJECT for fundamental
            # failures (feasibility, novelty, duplicate, verification
            # failed), HOLD otherwise.
            fundamental = {
                "feasibility", "novelty", "duplicate",
                "verification_outcome", "security_analysis",
                "security_regressions",
            }
            if set(failing) & fundamental:
                verdict = PromotionVerdict.REJECT
            else:
                verdict = PromotionVerdict.HOLD
            rationale = (
                f"failing gates: {sorted(failing)}"
            )

        self._decision_seq += 1
        decision = PromotionDecision(
            decision_id=f"dec-{self._decision_seq:08d}",
            candidate_id=candidate_id,
            problem_id=cand.problem_id,
            verdict=verdict,
            rationale=rationale,
            stage_reached=reached,
            failing_gates=tuple(failing),
            evidence_chain=tuple(evidence_chain),
            at=at,
        )
        self._decisions[decision.decision_id] = decision

        # Findings
        self._emit_stage_findings(cand, sim, adv, ver, decision, at=at)

        # Persist
        rec = CandidateRecord(
            candidate_id=candidate_id, problem_id=cand.problem_id,
            name=cand.name, feasibility=cand.feasibility,
            novelty=cand.novelty,
            measurable_value=cand.measurable_value,
            stage_reached=reached, verdict=verdict, updated_at=at,
        )
        self._store.put(rec)
        if isinstance(self._store, SqliteInventionStore):
            self._store.put_decision(decision.decision_id, decision)

        self._violations = check_invariants(self.snapshot())
        return decision

    def evaluate_all(
        self, *, at: datetime,
    ) -> Tuple[PromotionDecision, ...]:
        out: List[PromotionDecision] = []
        for cid in sorted(self._candidates):
            out.append(self.evaluate_candidate(cid, at=at))
        return tuple(out)

    # ---- findings --------------------------------------------------------

    def _emit_stage_findings(
        self,
        cand: CandidateTechnology,
        sim: Optional[SimulationResult],
        adv: Optional[AdversarialTestResult],
        ver: Optional[VerificationResult],
        decision: PromotionDecision,
        *,
        at: datetime,
    ) -> None:
        # Problem / defense findings
        defense_for_problem = [
            d for d in self._defenses.values()
            if d.problem_id == cand.problem_id
        ]
        if not defense_for_problem:
            self._findings.append(InventionFinding(
                kind=FindingKind.NO_DEFENSE_EXISTS,
                subject_id=cand.problem_id,
                detail="no current defense exists for the problem",
                severity=4, stage=PipelineStage.CURRENT_DEFENSE, at=at,
            ))
        else:
            for d in defense_for_problem:
                if d.coverage < 0.7:
                    self._findings.append(InventionFinding(
                        kind=FindingKind.DEFENSE_INSUFFICIENT,
                        subject_id=d.defense_id,
                        detail=(
                            f"current defense coverage "
                            f"{d.coverage:.2f} < 0.7"
                        ),
                        severity=3,
                        stage=PipelineStage.DEFENSE_LIMITATION,
                        at=at,
                    ))

        # Candidate-level
        if cand.novelty is NoveltyClass.DUPLICATE:
            self._findings.append(InventionFinding(
                kind=FindingKind.CANDIDATE_DUPLICATE,
                subject_id=cand.candidate_id,
                detail="candidate is a duplicate of existing defense",
                severity=4,
                stage=PipelineStage.CANDIDATE_TECHNOLOGY, at=at,
            ))
        if cand.measurable_value < self._gates.min_value:
            self._findings.append(InventionFinding(
                kind=FindingKind.CANDIDATE_LOW_VALUE,
                subject_id=cand.candidate_id,
                detail=(
                    f"measurable value {cand.measurable_value:.2f} < "
                    f"{self._gates.min_value:.2f}"
                ),
                severity=3,
                stage=PipelineStage.CANDIDATE_TECHNOLOGY, at=at,
            ))

        # Simulation
        if sim is not None and sim.success_rate < \
                self._gates.min_simulation_success:
            self._findings.append(InventionFinding(
                kind=FindingKind.SIMULATION_FAILED,
                subject_id=cand.candidate_id,
                detail=(
                    f"simulation success {sim.success_rate:.2f} < "
                    f"{self._gates.min_simulation_success:.2f}"
                ),
                severity=4, stage=PipelineStage.SIMULATION, at=at,
            ))

        # Adversarial
        if adv is not None and adv.survival_rate < \
                self._gates.min_adversarial_survival:
            self._findings.append(InventionFinding(
                kind=FindingKind.ADVERSARIAL_SURVIVAL_LOW,
                subject_id=cand.candidate_id,
                detail=(
                    f"adversarial survival {adv.survival_rate:.2f} < "
                    f"{self._gates.min_adversarial_survival:.2f}"
                ),
                severity=4,
                stage=PipelineStage.ADVERSARIAL_TEST, at=at,
            ))

        # Verification
        if ver is not None and verification_rank(ver.outcome) < \
                verification_rank(self._gates.min_verification):
            self._findings.append(InventionFinding(
                kind=FindingKind.VERIFICATION_FAILED,
                subject_id=cand.candidate_id,
                detail=(
                    f"verification outcome {ver.outcome.value} < "
                    f"{self._gates.min_verification.value}"
                ),
                severity=4,
                stage=PipelineStage.VERIFICATION, at=at,
            ))

        # Promotion outcome
        if decision.verdict is PromotionVerdict.PROMOTE:
            self._findings.append(InventionFinding(
                kind=FindingKind.PROMOTED,
                subject_id=cand.candidate_id,
                detail=decision.rationale,
                severity=2, stage=PipelineStage.PROMOTION, at=at,
            ))
        elif decision.verdict is PromotionVerdict.REJECT:
            self._findings.append(InventionFinding(
                kind=FindingKind.REJECTED,
                subject_id=cand.candidate_id,
                detail=decision.rationale,
                severity=3, stage=PipelineStage.PROMOTION, at=at,
            ))

    # ---- snapshot --------------------------------------------------------

    def findings(self) -> Tuple[InventionFinding, ...]:
        return tuple(self._findings)

    def findings_by_kind(self) -> Mapping[FindingKind, int]:
        out: Dict[FindingKind, int] = {k: 0 for k in FindingKind}
        for f in self._findings:
            out[f.kind] += 1
        return out

    def promoted(self) -> Tuple[PromotionDecision, ...]:
        return tuple(
            d for d in self._decisions.values()
            if d.verdict is PromotionVerdict.PROMOTE
        )

    def rejected(self) -> Tuple[PromotionDecision, ...]:
        return tuple(
            d for d in self._decisions.values()
            if d.verdict is PromotionVerdict.REJECT
        )

    def on_hold(self) -> Tuple[PromotionDecision, ...]:
        return tuple(
            d for d in self._decisions.values()
            if d.verdict is PromotionVerdict.HOLD
        )

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return check_invariants(self.snapshot())

    def record(self, candidate_id: str) -> Optional[CandidateRecord]:
        return self._store.get(candidate_id)

    def snapshot(self) -> InventionSnapshot:
        return InventionSnapshot(
            problems=dict(self._problems),
            defenses=dict(self._defenses),
            limitations=dict(self._limitations),
            capabilities=dict(self._capabilities),
            candidates=dict(self._candidates),
            simulations=dict(self._simulations),
            adversarial_tests=dict(self._adversarial),
            verifications=dict(self._verifications),
            decisions=dict(self._decisions),
            findings=tuple(self._findings),
        )


# =============================================================================
# SECTION 15 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _problem(
    pid: str = "p1",
    sev: ProblemSeverity = ProblemSeverity.HIGH,
    domain: str = "network",
) -> Problem:
    return Problem(
        problem_id=pid, title="Test problem",
        description="Test description", severity=sev, domain=domain,
        detected_at=_t0(),
    )


def _defense(
    did: str = "d1", pid: str = "p1",
    coverage: float = 0.5, confidence: float = 0.7,
) -> CurrentDefense:
    return CurrentDefense(
        defense_id=did, problem_id=pid, name="Test defense",
        description="Test", coverage=coverage, confidence=confidence,
    )


def _limitation(
    lid: str = "l1", pid: str = "p1", defense_id: Optional[str] = "d1",
    gap: float = 0.6,
) -> DefenseLimitation:
    return DefenseLimitation(
        limitation_id=lid, problem_id=pid, defense_id=defense_id,
        description="Limited coverage", severity=ProblemSeverity.HIGH,
        gap_score=gap, detected_at=_t0(),
    )


def _capability(
    cid: str = "c1", pid: str = "p1", lid: str = "l1",
) -> MissingCapability:
    return MissingCapability(
        capability_id=cid, problem_id=pid, limitation_id=lid,
        name="Independent detection", description="x",
        required_properties=frozenset({"independent", "realtime"}),
        at=_t0(),
    )


def _candidate(
    cid: str = "cand1", pid: str = "p1", cap_id: str = "c1",
    feasibility: FeasibilityClass = FeasibilityClass.FEASIBLE,
    novelty: NoveltyClass = NoveltyClass.NOVEL,
    value: float = 0.7,
    security_passed: bool = True,
) -> CandidateTechnology:
    return CandidateTechnology(
        candidate_id=cid, problem_id=pid, capability_id=cap_id,
        name="Candidate", description="x", approach="y",
        feasibility=feasibility, novelty=novelty,
        measurable_value=value,
        security_analysis_passed=security_passed,
        proposed_at=_t0(),
    )


def _simulation(
    cid: str = "cand1", run: int = 10, passed: int = 8,
    success_rate: float = 0.8,
    side_effects: float = 0.2, overhead: float = 0.2,
) -> SimulationResult:
    return SimulationResult(
        simulation_id="sim1", candidate_id=cid,
        scenarios_run=run, scenarios_passed=passed,
        success_rate=success_rate,
        side_effect_score=side_effects,
        performance_overhead=overhead,
        at=_t0(),
    )


def _adversarial(
    cid: str = "cand1", attempted: int = 10, survived: int = 9,
    survival: float = 0.9, worst_loss: float = 0.1,
) -> AdversarialTestResult:
    return AdversarialTestResult(
        test_id="adv1", candidate_id=cid,
        attacks_attempted=attempted, attacks_survived=survived,
        survival_rate=survival, worst_case_loss=worst_loss,
        at=_t0(),
    )


def _verification(
    cid: str = "cand1",
    outcome: VerificationOutcome = VerificationOutcome.PASSED,
    verifiers: Tuple[str, ...] = ("independent-1",),
    uncertainty: float = 0.1,
) -> VerificationResult:
    return VerificationResult(
        verification_id="ver1", candidate_id=cid,
        outcome=outcome, independent_verifiers=verifiers,
        evidence=("evidence-1",),
        residual_uncertainty=uncertainty, at=_t0(),
    )


def _fresh_engine() -> DefensiveInventionEngine:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_defense(_defense())
    eng.register_limitation(_limitation())
    eng.register_capability(_capability())
    eng.register_candidate(_candidate())
    return eng


# ---- domain ----

def test_problem_requires_id() -> None:
    try:
        Problem(
            problem_id="", title="t", description="d",
            severity=ProblemSeverity.HIGH, domain="x",
            detected_at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_defense_coverage_bounds() -> None:
    try:
        _defense(coverage=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_limitation_gap_bounds() -> None:
    try:
        _limitation(gap=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_capability_requires_properties() -> None:
    try:
        MissingCapability(
            capability_id="c", problem_id="p", limitation_id="l",
            name="x", description="y",
            required_properties=frozenset(), at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_candidate_value_bounds() -> None:
    try:
        _candidate(value=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_simulation_passed_le_run() -> None:
    try:
        SimulationResult(
            simulation_id="s", candidate_id="c",
            scenarios_run=5, scenarios_passed=10,
            success_rate=0.5, side_effect_score=0.1,
            performance_overhead=0.1, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_adversarial_survived_le_attempted() -> None:
    try:
        AdversarialTestResult(
            test_id="t", candidate_id="c",
            attacks_attempted=5, attacks_survived=10,
            survival_rate=0.5, worst_case_loss=0.1, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_feasibility_rank_ordering() -> None:
    assert feasibility_rank(FeasibilityClass.INFEASIBLE) < \
        feasibility_rank(FeasibilityClass.UNCERTAIN)
    assert feasibility_rank(FeasibilityClass.UNCERTAIN) < \
        feasibility_rank(FeasibilityClass.FEASIBLE)
    assert feasibility_rank(FeasibilityClass.FEASIBLE) < \
        feasibility_rank(FeasibilityClass.STRONGLY_FEASIBLE)


def test_novelty_rank_ordering() -> None:
    assert novelty_rank(NoveltyClass.DUPLICATE) < \
        novelty_rank(NoveltyClass.MARGINAL)
    assert novelty_rank(NoveltyClass.MARGINAL) < \
        novelty_rank(NoveltyClass.NOVEL)
    assert novelty_rank(NoveltyClass.NOVEL) < \
        novelty_rank(NoveltyClass.NOVEL_INVENTION)


def test_verification_rank_ordering() -> None:
    assert verification_rank(VerificationOutcome.FAILED) < \
        verification_rank(VerificationOutcome.WEAK_PASS)
    assert verification_rank(VerificationOutcome.WEAK_PASS) < \
        verification_rank(VerificationOutcome.PASSED)
    assert verification_rank(VerificationOutcome.PASSED) < \
        verification_rank(VerificationOutcome.STRONG_PASS)


def test_pipeline_order() -> None:
    assert PIPELINE_ORDER[0] is PipelineStage.PROBLEM
    assert PIPELINE_ORDER[-1] is PipelineStage.PROMOTION
    assert stage_index(PipelineStage.SIMULATION) < \
        stage_index(PipelineStage.ADVERSARIAL_TEST)


# ---- engine registration ----

def test_engine_registers_problem() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    assert eng.problem("p1") is not None


def test_engine_rejects_duplicate_problem() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    try:
        eng.register_problem(_problem())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_defense_requires_problem() -> None:
    eng = DefensiveInventionEngine()
    try:
        eng.register_defense(_defense())
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_limitation_requires_defense() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    try:
        eng.register_limitation(_limitation(defense_id="ghost"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_capability_requires_limitation() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    try:
        eng.register_capability(_capability(lid="ghost"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_candidate_requires_capability() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    try:
        eng.register_candidate(_candidate(cap_id="ghost"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_simulation_requires_candidate() -> None:
    eng = DefensiveInventionEngine()
    try:
        eng.record_simulation(_simulation(cid="ghost"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_adversarial_requires_candidate() -> None:
    eng = DefensiveInventionEngine()
    try:
        eng.record_adversarial(_adversarial(cid="ghost"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_verification_requires_candidate() -> None:
    eng = DefensiveInventionEngine()
    try:
        eng.record_verification(_verification(cid="ghost"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


# ---- evaluation ----

def test_engine_evaluate_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = _fresh_engine()
    try:
        eng.evaluate_candidate("cand1", at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_evaluate_unknown_candidate() -> None:
    eng = _fresh_engine()
    try:
        eng.evaluate_candidate("ghost", at=_t0())
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_promotion_requires_all_stages() -> None:
    eng = _fresh_engine()
    # No simulation/adversarial/verification
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is not PromotionVerdict.PROMOTE
    assert "simulation_missing" in decision.failing_gates
    assert "adversarial_missing" in decision.failing_gates
    assert "verification_missing" in decision.failing_gates


def test_engine_full_pass_promotes() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.PROMOTE
    assert decision.stage_reached is PipelineStage.PROMOTION
    assert not decision.failing_gates


def test_engine_promotion_evidence_chain_full() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    # Problem + Capability + Candidate + Simulation + Adversarial + Verification
    assert len(decision.evidence_chain) == 6


def test_engine_reject_on_duplicate_novelty() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate(novelty=NoveltyClass.DUPLICATE))
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.REJECT
    assert "duplicate" in decision.failing_gates


def test_engine_reject_on_low_feasibility() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate(
        feasibility=FeasibilityClass.INFEASIBLE,
    ))
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.REJECT
    assert "feasibility" in decision.failing_gates


def test_engine_reject_on_low_novelty() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate(novelty=NoveltyClass.MARGINAL))
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.REJECT


def test_engine_reject_on_security_analysis_failed() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate(security_passed=False))
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.REJECT
    assert "security_analysis" in decision.failing_gates


def test_engine_reject_on_verification_failed() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification(
        outcome=VerificationOutcome.FAILED,
    ))
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.REJECT


def test_engine_hold_on_simulation_marginal() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation(success_rate=0.5))
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.HOLD
    assert "simulation_success" in decision.failing_gates


def test_engine_hold_on_adversarial_marginal() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial(survival=0.5))
    eng.record_verification(_verification())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.HOLD
    assert "adversarial_survival" in decision.failing_gates


def test_engine_hold_on_low_value() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate(value=0.1))
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.HOLD
    assert "measurable_value" in decision.failing_gates


def test_engine_hold_on_verification_uncertainty() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification(uncertainty=0.8))
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.HOLD
    assert "verification_uncertainty" in decision.failing_gates


def test_engine_hold_on_no_independent_verifiers() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification(verifiers=()))
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.HOLD
    assert "verification_independents" in decision.failing_gates


# ---- findings ----

def test_engine_promoted_finding() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    eng.evaluate_candidate("cand1", at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.PROMOTED in kinds


def test_engine_rejected_finding() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate(
        feasibility=FeasibilityClass.INFEASIBLE,
    ))
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    eng.evaluate_candidate("cand1", at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.REJECTED in kinds


def test_engine_no_defense_finding() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate())
    eng.evaluate_candidate("cand1", at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.NO_DEFENSE_EXISTS in kinds


def test_engine_defense_insufficient_finding() -> None:
    eng = _fresh_engine()  # defense coverage 0.5
    eng.evaluate_candidate("cand1", at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.DEFENSE_INSUFFICIENT in kinds


def test_engine_duplicate_candidate_finding() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate(novelty=NoveltyClass.DUPLICATE))
    eng.evaluate_candidate("cand1", at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CANDIDATE_DUPLICATE in kinds


def test_engine_low_value_finding() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate(value=0.1))
    eng.evaluate_candidate("cand1", at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CANDIDATE_LOW_VALUE in kinds


def test_engine_simulation_failed_finding() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation(success_rate=0.3))
    eng.evaluate_candidate("cand1", at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.SIMULATION_FAILED in kinds


def test_engine_adversarial_low_finding() -> None:
    eng = _fresh_engine()
    eng.record_adversarial(_adversarial(survival=0.3))
    eng.evaluate_candidate("cand1", at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.ADVERSARIAL_SURVIVAL_LOW in kinds


def test_engine_verification_failed_finding() -> None:
    eng = _fresh_engine()
    eng.record_verification(_verification(
        outcome=VerificationOutcome.FAILED,
    ))
    eng.evaluate_candidate("cand1", at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.VERIFICATION_FAILED in kinds


# ---- evaluation bulk ----

def test_engine_evaluate_all() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    decisions = eng.evaluate_all(at=_t0())
    assert len(decisions) == 1


def test_engine_promoted_lookup() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    eng.evaluate_candidate("cand1", at=_t0())
    assert len(eng.promoted()) == 1


def test_engine_rejected_lookup() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate(
        feasibility=FeasibilityClass.INFEASIBLE,
    ))
    eng.evaluate_candidate("cand1", at=_t0())
    assert len(eng.rejected()) == 1


def test_engine_hold_lookup() -> None:
    eng = _fresh_engine()
    # No records → HOLD
    eng.evaluate_candidate("cand1", at=_t0())
    assert len(eng.on_hold()) == 1


# ---- gates ----

def test_gates_defaults() -> None:
    gates = PromotionGates()
    assert gates.min_feasibility is FeasibilityClass.FEASIBLE
    assert gates.min_novelty is NoveltyClass.NOVEL


def test_gates_validation() -> None:
    try:
        PromotionGates(min_value=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_gates() -> None:
    eng = DefensiveInventionEngine()
    g = PromotionGates(min_value=0.9)
    eng.set_gates(g)
    assert eng.gates() is g


def test_engine_strict_gates_cause_hold() -> None:
    eng = _fresh_engine()
    eng.set_gates(PromotionGates(min_simulation_success=0.99))
    eng.record_simulation(_simulation(success_rate=0.8))
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    assert decision.verdict is PromotionVerdict.HOLD


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = _fresh_engine()
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    eng.evaluate_candidate("cand1", at=_t0())
    assert eng.violations() == ()


def test_invariant_promote_not_duplicate() -> None:
    # Craft a scenario with a promoted duplicate directly
    eng = DefensiveInventionEngine()
    # Register a valid chain
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate(novelty=NoveltyClass.DUPLICATE))
    eng.record_simulation(_simulation())
    eng.record_adversarial(_adversarial())
    eng.record_verification(_verification())
    # Force a PROMOTE by mutation
    from dataclasses import replace as _replace
    decision = eng.evaluate_candidate("cand1", at=_t0())
    # decision should be REJECT (duplicate); let's override for invariant test
    bad = _replace(
        decision, verdict=PromotionVerdict.PROMOTE,
        failing_gates=(), stage_reached=PipelineStage.PROMOTION,
    )
    eng._decisions[bad.decision_id] = bad
    v = eng.violations()
    assert any(
        x.invariant_id == "inv.promote_not_duplicate" for x in v
    )


def test_invariant_no_promote_without_simulation() -> None:
    eng = DefensiveInventionEngine()
    eng.register_problem(_problem())
    eng.register_limitation(_limitation(defense_id=None))
    eng.register_capability(_capability())
    eng.register_candidate(_candidate())
    decision = eng.evaluate_candidate("cand1", at=_t0())
    # decision is HOLD (missing simulation); force to PROMOTE
    from dataclasses import replace as _replace
    bad = _replace(
        decision, verdict=PromotionVerdict.PROMOTE,
        failing_gates=(), stage_reached=PipelineStage.PROMOTION,
        evidence_chain=(*decision.evidence_chain, "fake"),
    )
    eng._decisions[bad.decision_id] = bad
    v = eng.violations()
    assert any(
        x.invariant_id == "inv.promote_requires_simulation" for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryInventionStore()
    t = _t0()
    s.put(CandidateRecord(
        "c", "p", "n", FeasibilityClass.FEASIBLE,
        NoveltyClass.NOVEL, 0.5, PipelineStage.SIMULATION,
        PromotionVerdict.HOLD, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(CandidateRecord(
            "c", "p", "n", FeasibilityClass.FEASIBLE,
            NoveltyClass.NOVEL, 0.5, PipelineStage.SIMULATION,
            PromotionVerdict.HOLD, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "invention.db")
    store = SqliteInventionStore(db)
    store.put(CandidateRecord(
        "c1", "p1", "n", FeasibilityClass.STRONGLY_FEASIBLE,
        NoveltyClass.NOVEL_INVENTION, 0.9, PipelineStage.PROMOTION,
        PromotionVerdict.PROMOTE, _t0(),
    ))
    got = store.get("c1")
    assert got is not None
    assert got.feasibility is FeasibilityClass.STRONGLY_FEASIBLE
    assert got.verdict is PromotionVerdict.PROMOTE


def test_sqlite_store_decision_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "invention.db")
    store = SqliteInventionStore(db)
    d = PromotionDecision(
        decision_id="dec1", candidate_id="c1", problem_id="p1",
        verdict=PromotionVerdict.PROMOTE, rationale="ok",
        stage_reached=PipelineStage.PROMOTION,
        failing_gates=(),
        evidence_chain=("p1", "c1", "s1", "a1", "v1"),
        at=_t0(),
    )
    store.put_decision("dec1", d)
    row = store._conn.execute(
        "SELECT payload_json FROM invention_decisions "
        "WHERE decision_id = 'dec1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["verdict"] == "promote"


# =============================================================================
# SECTION 16 — MANUAL RUNNER
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
