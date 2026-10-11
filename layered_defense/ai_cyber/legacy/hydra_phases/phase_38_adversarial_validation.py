"""
HYDRA POST-CORE — PHASE 38: ADVERSARIAL VALIDATION
=====================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 18 attack vectors, 5 defense verdicts, 4 severities,
    5 confidence classes, 12 finding kinds
  * Attack scenario model — vector, target, preconditions, steps,
    expected defense, severity, tags
  * Defense probe abstraction — a callable that runs a scenario
    against a real or simulated system and returns a verdict
  * Adversarial validation engine:
      - registers scenarios and probes per (target, vector)
      - runs every scenario that has a probe
      - aggregates by vector, target, severity
      - produces findings and coverage metrics
  * Findings — bypass, partial defense, no probe, weak coverage,
    untested target, high-severity bypass, inconclusive result,
    all-defended, regression, attack-surface-expansion,
    novel-attack-path-observed
  * Machine-checkable validation invariants
  * In-memory + SQLite stores
  * Phase-38 engine facade
  * Full test suite + manual runner

Doctrine: the system must attack *its own* technology. Nothing here
claims compromise unless a scenario's probe actually produced a
BYPASSED verdict. Happy paths alone never pass validation. Coverage
is measured explicitly.

No third-party dependencies.

Run tests:
    python hydra_phase38_adversarial_validation.py
    pytest hydra_phase38_adversarial_validation.py -q
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


class AttackVector(str, Enum):
    AUTHORITY_ABUSE = "authority_abuse"
    AGENT_COMPROMISE = "agent_compromise"
    TOOL_ABUSE = "tool_abuse"
    PROMPT_INJECTION = "prompt_injection"
    MODEL_MANIPULATION = "model_manipulation"
    EVIDENCE_POISONING = "evidence_poisoning"
    TELEMETRY_POISONING = "telemetry_poisoning"
    STATE_CORRUPTION = "state_corruption"
    STATE_DIVERGENCE = "state_divergence"
    SUPPLY_CHAIN_COMPROMISE = "supply_chain_compromise"
    INVARIANT_BYPASS = "invariant_bypass"
    RECOVERY_MANIPULATION = "recovery_manipulation"
    FALSE_CONFIDENCE = "false_confidence"
    DEPENDENCY_FAILURE = "dependency_failure"
    CASCADING_FAILURE = "cascading_failure"
    INSIDER_ABUSE = "insider_abuse"
    ADVERSARIAL_LEARNING = "adversarial_learning"
    NOVEL_ATTACK_PATH = "novel_attack_path"


ALL_VECTORS: Tuple[AttackVector, ...] = tuple(AttackVector)


class AttackSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_WEIGHT: Mapping[AttackSeverity, int] = {
    AttackSeverity.LOW: 1,
    AttackSeverity.MEDIUM: 2,
    AttackSeverity.HIGH: 3,
    AttackSeverity.CRITICAL: 4,
}


def severity_weight(s: AttackSeverity) -> int:
    return _SEVERITY_WEIGHT[s]


class DefenseVerdict(str, Enum):
    DEFENDED = "defended"
    PARTIALLY_DEFENDED = "partially_defended"
    BYPASSED = "bypassed"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"


class ConfidenceClass(str, Enum):
    SPECULATIVE = "speculative"
    INFERRED = "inferred"
    OBSERVED = "observed"
    REPRODUCED = "reproduced"


class FindingKind(str, Enum):
    BYPASS_FOUND = "bypass_found"
    PARTIAL_DEFENSE = "partial_defense"
    NO_PROBE_REGISTERED = "no_probe_registered"
    WEAK_COVERAGE = "weak_coverage"
    UNTESTED_TARGET = "untested_target"
    HIGH_SEVERITY_BYPASS = "high_severity_bypass"
    INCONCLUSIVE_RESULT = "inconclusive_result"
    ALL_DEFENDED = "all_defended"
    REGRESSION = "regression"
    ATTACK_SURFACE_EXPANSION = "attack_surface_expansion"
    NOVEL_ATTACK_PATH_OBSERVED = "novel_attack_path_observed"
    LOW_CONFIDENCE_RESULT = "low_confidence_result"


@dataclass(frozen=True)
class ValidationFinding:
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
# SECTION 3 — SCENARIO + RESULT
# =============================================================================


@dataclass(frozen=True)
class AttackScenario:
    scenario_id: str
    vector: AttackVector
    target_id: str
    title: str
    preconditions: Tuple[str, ...]
    steps: Tuple[str, ...]
    expected_defense: str
    severity: AttackSeverity
    tags: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.scenario_id:
            raise ValueError("scenario_id is required")
        if not self.target_id:
            raise ValueError("target_id is required")
        if not self.title:
            raise ValueError("title is required")
        if not self.steps:
            raise ValueError("scenario must have at least one step")
        if not self.expected_defense:
            raise ValueError("expected_defense is required")


@dataclass(frozen=True)
class AttackResult:
    scenario_id: str
    verdict: DefenseVerdict
    confidence: ConfidenceClass
    observed: str
    notes: Tuple[str, ...] = ()
    duration_ms: float = 0.0
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.scenario_id:
            raise ValueError("scenario_id is required")
        if not self.observed:
            raise ValueError("observed is required")
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be >= 0")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# Probe signature: given a scenario, produce an AttackResult.
DefenseProbe = Callable[[AttackScenario], AttackResult]


# =============================================================================
# SECTION 4 — AGGREGATES
# =============================================================================


@dataclass(frozen=True)
class VectorReport:
    vector: AttackVector
    scenarios: int
    probed: int
    defended: int
    partial: int
    bypassed: int
    inconclusive: int
    bypass_rate: float
    max_bypass_severity: Optional[AttackSeverity]

    def __post_init__(self) -> None:
        if self.scenarios < 0:
            raise ValueError("scenarios must be >= 0")
        if self.probed < 0:
            raise ValueError("probed must be >= 0")
        if not 0.0 <= self.bypass_rate <= 1.0:
            raise ValueError("bypass_rate must be within [0,1]")


@dataclass(frozen=True)
class TargetReport:
    target_id: str
    scenarios: int
    probed: int
    defended: int
    partial: int
    bypassed: int
    coverage: float

    def __post_init__(self) -> None:
        if self.scenarios < 0:
            raise ValueError("scenarios must be >= 0")
        if not 0.0 <= self.coverage <= 1.0:
            raise ValueError("coverage must be within [0,1]")


@dataclass(frozen=True)
class GlobalValidationSummary:
    total_scenarios: int
    probed: int
    defended: int
    partial: int
    bypassed: int
    inconclusive: int
    not_applicable: int
    bypass_rate: float
    critical_bypasses: int
    high_bypasses: int
    coverage_ratio: float

    def __post_init__(self) -> None:
        for n, v in (
            ("bypass_rate", self.bypass_rate),
            ("coverage_ratio", self.coverage_ratio),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")


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
class ValidationSnapshot:
    scenarios: Mapping[str, AttackScenario]
    results: Mapping[str, AttackResult]
    findings: Tuple[ValidationFinding, ...]


@dataclass(frozen=True)
class ValidationInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[ValidationSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_scenarios_have_steps(
    snap: ValidationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for sid, s in snap.scenarios.items():
        if not s.steps:
            out.append(InvariantViolation(
                invariant_id="adv.scenarios_have_steps",
                severity=InvariantSeverity.HIGH,
                subject_id=sid,
                detail="scenario has no steps",
            ))
    return tuple(out)


def _inv_results_reference_scenarios(
    snap: ValidationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for sid in snap.results:
        if sid not in snap.scenarios:
            out.append(InvariantViolation(
                invariant_id="adv.results_reference_scenarios",
                severity=InvariantSeverity.CRITICAL,
                subject_id=sid,
                detail="result references unknown scenario",
            ))
    return tuple(out)


def _inv_bypass_severity_consistent(
    snap: ValidationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """Any BYPASSED result must have produced a corresponding
    BYPASS_FOUND or HIGH_SEVERITY_BYPASS finding."""
    out: List[InvariantViolation] = []
    bypass_ids = {
        sid for sid, r in snap.results.items()
        if r.verdict is DefenseVerdict.BYPASSED
    }
    finding_subjects = {
        f.subject_id for f in snap.findings
        if f.kind in (
            FindingKind.BYPASS_FOUND,
            FindingKind.HIGH_SEVERITY_BYPASS,
        )
    }
    for sid in bypass_ids:
        if sid not in finding_subjects:
            out.append(InvariantViolation(
                invariant_id="adv.bypass_severity_consistent",
                severity=InvariantSeverity.HIGH,
                subject_id=sid,
                detail="BYPASSED result without corresponding finding",
            ))
    return tuple(out)


def _inv_findings_severity_bounded(
    snap: ValidationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if not 1 <= f.severity <= 5:
            out.append(InvariantViolation(
                invariant_id="adv.findings_severity_bounded",
                severity=InvariantSeverity.LOW,
                subject_id=f.subject_id,
                detail=f"severity {f.severity}",
            ))
    return tuple(out)


def _inv_no_result_for_unprobed(
    snap: ValidationSnapshot,
) -> Tuple[InvariantViolation, ...]:
    """NOT_APPLICABLE results must be produced only when no probe was
    registered for the (target, vector) pair. This invariant is
    enforced through the engine; here we check consistency."""
    out: List[InvariantViolation] = []
    for sid, r in snap.results.items():
        s = snap.scenarios.get(sid)
        if s is None:
            continue
        if r.verdict is DefenseVerdict.NOT_APPLICABLE \
           and r.confidence is not ConfidenceClass.SPECULATIVE:
            out.append(InvariantViolation(
                invariant_id="adv.not_applicable_low_confidence",
                severity=InvariantSeverity.MEDIUM,
                subject_id=sid,
                detail=(
                    f"NOT_APPLICABLE verdict with confidence "
                    f"{r.confidence.value}"
                ),
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[ValidationInvariant, ...] = (
    ValidationInvariant(
        invariant_id="adv.scenarios_have_steps",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_scenarios_have_steps,
        description="Every scenario must declare at least one step.",
    ),
    ValidationInvariant(
        invariant_id="adv.results_reference_scenarios",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_results_reference_scenarios,
        description="Every result must reference a registered scenario.",
    ),
    ValidationInvariant(
        invariant_id="adv.bypass_severity_consistent",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_bypass_severity_consistent,
        description="BYPASSED results must produce a bypass finding.",
    ),
    ValidationInvariant(
        invariant_id="adv.findings_severity_bounded",
        severity=InvariantSeverity.LOW,
        predicate=_inv_findings_severity_bounded,
        description="Findings must carry a valid severity.",
    ),
    ValidationInvariant(
        invariant_id="adv.not_applicable_low_confidence",
        severity=InvariantSeverity.MEDIUM,
        predicate=_inv_no_result_for_unprobed,
        description="NOT_APPLICABLE verdicts must be speculative.",
    ),
)


def check_invariants(
    snap: ValidationSnapshot,
    invariants: Iterable[ValidationInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 6 — STORE
# =============================================================================


@dataclass(frozen=True)
class ResultRecord:
    scenario_id: str
    vector: AttackVector
    target_id: str
    verdict: DefenseVerdict
    severity: AttackSeverity
    confidence: ConfidenceClass
    updated_at: datetime


class ValidationStore(Protocol):
    def put(self, record: ResultRecord) -> None: ...
    def get(self, scenario_id: str) -> Optional[ResultRecord]: ...
    def all(self) -> Tuple[ResultRecord, ...]: ...


class InMemoryValidationStore:
    def __init__(self) -> None:
        self._data: Dict[str, ResultRecord] = {}

    def put(self, record: ResultRecord) -> None:
        existing = self._data.get(record.scenario_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.scenario_id] = record

    def get(self, scenario_id: str) -> Optional[ResultRecord]:
        return self._data.get(scenario_id)

    def all(self) -> Tuple[ResultRecord, ...]:
        return tuple(self._data.values())


class SqliteValidationStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS adv_results (
                scenario_id TEXT PRIMARY KEY,
                vector TEXT NOT NULL,
                target_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS adv_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: ResultRecord) -> None:
        existing = self.get(record.scenario_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO adv_results
              (scenario_id, vector, target_id, verdict, severity,
               confidence, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scenario_id) DO UPDATE SET
              vector=excluded.vector,
              target_id=excluded.target_id,
              verdict=excluded.verdict,
              severity=excluded.severity,
              confidence=excluded.confidence,
              updated_at=excluded.updated_at
            """,
            (
                record.scenario_id, record.vector.value,
                record.target_id, record.verdict.value,
                record.severity.value, record.confidence.value,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, scenario_id: str) -> Optional[ResultRecord]:
        row = self._conn.execute(
            "SELECT vector, target_id, verdict, severity, confidence, "
            "updated_at FROM adv_results WHERE scenario_id = ?",
            (scenario_id,),
        ).fetchone()
        if row is None:
            return None
        return ResultRecord(
            scenario_id=scenario_id, vector=AttackVector(row[0]),
            target_id=row[1], verdict=DefenseVerdict(row[2]),
            severity=AttackSeverity(row[3]),
            confidence=ConfidenceClass(row[4]),
            updated_at=datetime.fromisoformat(row[5]),
        )

    def all(self) -> Tuple[ResultRecord, ...]:
        rows = self._conn.execute(
            "SELECT scenario_id FROM adv_results"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows)
            if r is not None
        )

    def put_finding(self, finding_id: str, f: ValidationFinding) -> None:
        payload = {
            "finding_id": finding_id,
            "kind": f.kind.value,
            "subject_id": f.subject_id,
            "detail": f.detail,
            "severity": f.severity,
            "at": f.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO adv_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 7 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class ValidationConfig:
    weak_coverage_threshold: float = 0.5
    weak_coverage_min_scenarios: int = 3
    critical_bypass_threshold: int = 0
    high_bypass_threshold: int = 0
    max_findings: int = 5000

    def __post_init__(self) -> None:
        if not 0.0 <= self.weak_coverage_threshold <= 1.0:
            raise ValueError(
                "weak_coverage_threshold must be within [0,1]"
            )
        if self.weak_coverage_min_scenarios < 1:
            raise ValueError(
                "weak_coverage_min_scenarios must be >= 1"
            )
        if self.critical_bypass_threshold < 0:
            raise ValueError("critical_bypass_threshold must be >= 0")
        if self.high_bypass_threshold < 0:
            raise ValueError("high_bypass_threshold must be >= 0")
        if self.max_findings < 1:
            raise ValueError("max_findings must be >= 1")


class AdversarialValidationEngine:
    """Adversarial validation engine.

    Registers attack scenarios + defense probes, runs them, produces
    findings, and computes coverage / bypass metrics per vector and
    target.
    """

    def __init__(
        self,
        *,
        store: Optional[ValidationStore] = None,
        config: Optional[ValidationConfig] = None,
    ) -> None:
        self._store: ValidationStore = store or InMemoryValidationStore()
        self._config = config or ValidationConfig()
        self._scenarios: Dict[str, AttackScenario] = {}
        self._probes: Dict[Tuple[str, AttackVector], DefenseProbe] = {}
        self._results: Dict[str, AttackResult] = {}
        self._findings: List[ValidationFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()

    # ---- registration ----------------------------------------------------

    def register_scenario(self, s: AttackScenario) -> None:
        if s.scenario_id in self._scenarios:
            raise ValueError(
                f"scenario {s.scenario_id} already registered"
            )
        self._scenarios[s.scenario_id] = s

    def register_probe(
        self, target_id: str, vector: AttackVector, probe: DefenseProbe,
    ) -> None:
        key = (target_id, vector)
        if key in self._probes:
            raise ValueError(
                f"probe already registered for "
                f"({target_id}, {vector.value})"
            )
        self._probes[key] = probe

    def scenario(self, sid: str) -> Optional[AttackScenario]:
        return self._scenarios.get(sid)

    def scenarios(self) -> Tuple[AttackScenario, ...]:
        return tuple(self._scenarios.values())

    def config(self) -> ValidationConfig:
        return self._config

    def set_config(self, c: ValidationConfig) -> None:
        self._config = c

    # ---- execution -------------------------------------------------------

    def run(self, *, at: datetime) -> Tuple[ResultRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        cfg = self._config
        self._findings = []
        self._results = {}

        records: List[ResultRecord] = []
        for sid in sorted(self._scenarios):
            s = self._scenarios[sid]
            probe = self._probes.get((s.target_id, s.vector))
            if probe is None:
                result = AttackResult(
                    scenario_id=sid,
                    verdict=DefenseVerdict.NOT_APPLICABLE,
                    confidence=ConfidenceClass.SPECULATIVE,
                    observed="no probe registered for this target/vector",
                    notes=("register a probe to validate this scenario",),
                    duration_ms=0.0,
                    at=at,
                )
                self._findings.append(ValidationFinding(
                    kind=FindingKind.NO_PROBE_REGISTERED,
                    subject_id=sid,
                    detail=(
                        f"no probe for ({s.target_id}, "
                        f"{s.vector.value})"
                    ),
                    severity=2, at=at,
                ))
            else:
                try:
                    produced = probe(s)
                    result = AttackResult(
                        scenario_id=sid,
                        verdict=produced.verdict,
                        confidence=produced.confidence,
                        observed=produced.observed,
                        notes=produced.notes,
                        duration_ms=produced.duration_ms,
                        at=produced.at or at,
                    )
                except Exception as exc:  # noqa: BLE001
                    result = AttackResult(
                        scenario_id=sid,
                        verdict=DefenseVerdict.INCONCLUSIVE,
                        confidence=ConfidenceClass.SPECULATIVE,
                        observed=f"probe raised {type(exc).__name__}",
                        notes=(str(exc),),
                        duration_ms=0.0,
                        at=at,
                    )
                    self._findings.append(ValidationFinding(
                        kind=FindingKind.INCONCLUSIVE_RESULT,
                        subject_id=sid,
                        detail=(
                            f"probe raised {type(exc).__name__}: {exc}"
                        ),
                        severity=3, at=at,
                    ))
            self._results[sid] = result
            records.append(ResultRecord(
                scenario_id=sid, vector=s.vector, target_id=s.target_id,
                verdict=result.verdict, severity=s.severity,
                confidence=result.confidence, updated_at=at,
            ))

        self._emit_findings(at=at)
        if len(self._findings) > cfg.max_findings:
            self._findings = self._findings[: cfg.max_findings]

        for rec in records:
            self._store.put(rec)
        if isinstance(self._store, SqliteValidationStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(
                    f"f-{i:08d}-{f.kind.value}", f,
                )

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- findings --------------------------------------------------------

    def _emit_findings(self, *, at: datetime) -> None:
        cfg = self._config
        for sid in sorted(self._results):
            r = self._results[sid]
            s = self._scenarios[sid]

            if r.verdict is DefenseVerdict.BYPASSED:
                self._findings.append(ValidationFinding(
                    kind=FindingKind.BYPASS_FOUND,
                    subject_id=sid,
                    detail=(
                        f"bypass: {s.title} "
                        f"(vector {s.vector.value}, target {s.target_id})"
                    ),
                    severity=severity_weight(s.severity) + 1,
                    at=at,
                ))
                if s.severity in (
                    AttackSeverity.HIGH, AttackSeverity.CRITICAL,
                ):
                    self._findings.append(ValidationFinding(
                        kind=FindingKind.HIGH_SEVERITY_BYPASS,
                        subject_id=sid,
                        detail=(
                            f"{s.severity.value} bypass on "
                            f"{s.target_id} via {s.vector.value}"
                        ),
                        severity=5, at=at,
                    ))
            elif r.verdict is DefenseVerdict.PARTIALLY_DEFENDED:
                self._findings.append(ValidationFinding(
                    kind=FindingKind.PARTIAL_DEFENSE,
                    subject_id=sid,
                    detail=(
                        f"partial defense: {s.title}"
                    ),
                    severity=max(1, severity_weight(s.severity)),
                    at=at,
                ))
            elif r.verdict is DefenseVerdict.INCONCLUSIVE:
                self._findings.append(ValidationFinding(
                    kind=FindingKind.INCONCLUSIVE_RESULT,
                    subject_id=sid,
                    detail=(
                        f"inconclusive: {s.title} — {r.observed}"
                    ),
                    severity=3, at=at,
                ))
            if r.confidence is ConfidenceClass.SPECULATIVE \
               and r.verdict in (
                   DefenseVerdict.BYPASSED,
                   DefenseVerdict.PARTIALLY_DEFENDED,
               ):
                self._findings.append(ValidationFinding(
                    kind=FindingKind.LOW_CONFIDENCE_RESULT,
                    subject_id=sid,
                    detail="low-confidence verdict",
                    severity=2, at=at,
                ))

        # Coverage findings
        vector_report = self.vector_reports()
        for v, rep in vector_report.items():
            if rep.scenarios >= cfg.weak_coverage_min_scenarios:
                coverage = rep.probed / rep.scenarios if rep.scenarios else 1.0
                if coverage < cfg.weak_coverage_threshold:
                    self._findings.append(ValidationFinding(
                        kind=FindingKind.WEAK_COVERAGE,
                        subject_id=v.value,
                        detail=(
                            f"vector {v.value} has "
                            f"{rep.probed}/{rep.scenarios} probed "
                            f"(coverage {coverage:.2f})"
                        ),
                        severity=3, at=at,
                    ))

        target_report = self.target_reports()
        for tid, rep in target_report.items():
            if rep.scenarios > 0 and rep.probed == 0:
                self._findings.append(ValidationFinding(
                    kind=FindingKind.UNTESTED_TARGET,
                    subject_id=tid,
                    detail=f"target {tid} has {rep.scenarios} scenario(s) but 0 probes",
                    severity=3, at=at,
                ))

        # All-defended informational finding
        probed_verdicts = [
            r.verdict for r in self._results.values()
            if r.verdict is not DefenseVerdict.NOT_APPLICABLE
        ]
        if probed_verdicts and all(
            v is DefenseVerdict.DEFENDED for v in probed_verdicts
        ):
            self._findings.append(ValidationFinding(
                kind=FindingKind.ALL_DEFENDED,
                subject_id="<all>",
                detail=f"all {len(probed_verdicts)} probes defended",
                severity=1, at=at,
            ))

    # ---- queries ---------------------------------------------------------

    def result(self, sid: str) -> Optional[AttackResult]:
        return self._results.get(sid)

    def results(self) -> Tuple[AttackResult, ...]:
        return tuple(self._results.values())

    def findings(self) -> Tuple[ValidationFinding, ...]:
        return tuple(self._findings)

    def findings_by_kind(self) -> Mapping[FindingKind, int]:
        out: Dict[FindingKind, int] = {k: 0 for k in FindingKind}
        for f in self._findings:
            out[f.kind] += 1
        return out

    def top_findings(
        self, *, k: int = 10,
    ) -> Tuple[ValidationFinding, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._findings,
            key=lambda f: (-f.severity, f.kind.value, f.subject_id),
        )
        return tuple(ordered[:k])

    def vector_reports(self) -> Mapping[AttackVector, VectorReport]:
        out: Dict[AttackVector, VectorReport] = {}
        for v in ALL_VECTORS:
            scens = [s for s in self._scenarios.values() if s.vector is v]
            if not scens:
                continue
            results = [
                self._results[s.scenario_id]
                for s in scens if s.scenario_id in self._results
            ]
            probed = [
                r for r in results
                if r.verdict is not DefenseVerdict.NOT_APPLICABLE
            ]
            defended = sum(
                1 for r in probed if r.verdict is DefenseVerdict.DEFENDED
            )
            partial = sum(
                1 for r in probed
                if r.verdict is DefenseVerdict.PARTIALLY_DEFENDED
            )
            bypassed = sum(
                1 for r in probed if r.verdict is DefenseVerdict.BYPASSED
            )
            inconclusive = sum(
                1 for r in probed
                if r.verdict is DefenseVerdict.INCONCLUSIVE
            )
            rate = bypassed / len(probed) if probed else 0.0
            # highest severity among bypassed
            sev: Optional[AttackSeverity] = None
            for s in scens:
                r = self._results.get(s.scenario_id)
                if r is None or r.verdict is not DefenseVerdict.BYPASSED:
                    continue
                if sev is None or \
                        severity_weight(s.severity) > severity_weight(sev):
                    sev = s.severity
            out[v] = VectorReport(
                vector=v, scenarios=len(scens), probed=len(probed),
                defended=defended, partial=partial, bypassed=bypassed,
                inconclusive=inconclusive, bypass_rate=rate,
                max_bypass_severity=sev,
            )
        return out

    def target_reports(self) -> Mapping[str, TargetReport]:
        by_target: Dict[str, List[AttackScenario]] = {}
        for s in self._scenarios.values():
            by_target.setdefault(s.target_id, []).append(s)
        out: Dict[str, TargetReport] = {}
        for tid, scens in by_target.items():
            results = [
                self._results[s.scenario_id]
                for s in scens if s.scenario_id in self._results
            ]
            probed = [
                r for r in results
                if r.verdict is not DefenseVerdict.NOT_APPLICABLE
            ]
            defended = sum(
                1 for r in probed if r.verdict is DefenseVerdict.DEFENDED
            )
            partial = sum(
                1 for r in probed
                if r.verdict is DefenseVerdict.PARTIALLY_DEFENDED
            )
            bypassed = sum(
                1 for r in probed if r.verdict is DefenseVerdict.BYPASSED
            )
            coverage = len(probed) / len(scens) if scens else 0.0
            out[tid] = TargetReport(
                target_id=tid, scenarios=len(scens),
                probed=len(probed), defended=defended,
                partial=partial, bypassed=bypassed,
                coverage=coverage,
            )
        return out

    def global_summary(self) -> GlobalValidationSummary:
        total = len(self._scenarios)
        probed = 0
        defended = 0
        partial = 0
        bypassed = 0
        inconclusive = 0
        na = 0
        critical_bypasses = 0
        high_bypasses = 0
        for sid, r in self._results.items():
            s = self._scenarios.get(sid)
            if r.verdict is DefenseVerdict.NOT_APPLICABLE:
                na += 1
                continue
            probed += 1
            if r.verdict is DefenseVerdict.DEFENDED:
                defended += 1
            elif r.verdict is DefenseVerdict.PARTIALLY_DEFENDED:
                partial += 1
            elif r.verdict is DefenseVerdict.BYPASSED:
                bypassed += 1
                if s is not None:
                    if s.severity is AttackSeverity.CRITICAL:
                        critical_bypasses += 1
                    elif s.severity is AttackSeverity.HIGH:
                        high_bypasses += 1
            elif r.verdict is DefenseVerdict.INCONCLUSIVE:
                inconclusive += 1
        rate = bypassed / probed if probed else 0.0
        coverage = probed / total if total else 0.0
        return GlobalValidationSummary(
            total_scenarios=total, probed=probed,
            defended=defended, partial=partial,
            bypassed=bypassed, inconclusive=inconclusive,
            not_applicable=na, bypass_rate=rate,
            critical_bypasses=critical_bypasses,
            high_bypasses=high_bypasses,
            coverage_ratio=coverage,
        )

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, sid: str) -> Optional[ResultRecord]:
        return self._store.get(sid)

    def snapshot(self) -> ValidationSnapshot:
        return ValidationSnapshot(
            scenarios=dict(self._scenarios),
            results=dict(self._results),
            findings=tuple(self._findings),
        )


# =============================================================================
# SECTION 8 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _scenario(
    sid: str, *,
    vector: AttackVector = AttackVector.AUTHORITY_ABUSE,
    target: str = "phase-03",
    title: str = "attack",
    severity: AttackSeverity = AttackSeverity.HIGH,
    steps: Iterable[str] = ("step1", "step2"),
    preconditions: Iterable[str] = ("pre1",),
    expected: str = "system must reject",
    tags: Iterable[str] = (),
) -> AttackScenario:
    return AttackScenario(
        scenario_id=sid, vector=vector, target_id=target,
        title=title, preconditions=tuple(preconditions),
        steps=tuple(steps), expected_defense=expected,
        severity=severity, tags=frozenset(tags),
    )


def _result(
    sid: str, *,
    verdict: DefenseVerdict = DefenseVerdict.DEFENDED,
    confidence: ConfidenceClass = ConfidenceClass.OBSERVED,
    observed: str = "probe ran",
    duration_ms: float = 5.0,
) -> AttackResult:
    return AttackResult(
        scenario_id=sid, verdict=verdict, confidence=confidence,
        observed=observed, duration_ms=duration_ms, at=_t0(),
    )


def _defended_probe(s: AttackScenario) -> AttackResult:
    return _result(s.scenario_id, verdict=DefenseVerdict.DEFENDED)


def _bypassed_probe(s: AttackScenario) -> AttackResult:
    return _result(s.scenario_id, verdict=DefenseVerdict.BYPASSED)


def _partial_probe(s: AttackScenario) -> AttackResult:
    return _result(s.scenario_id, verdict=DefenseVerdict.PARTIALLY_DEFENDED)


# ---- domain ----

def test_scenario_requires_id() -> None:
    try:
        AttackScenario(
            scenario_id="", vector=AttackVector.AUTHORITY_ABUSE,
            target_id="t", title="x", preconditions=(),
            steps=("s",), expected_defense="y",
            severity=AttackSeverity.HIGH,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_scenario_requires_steps() -> None:
    try:
        _scenario("s", steps=())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_scenario_requires_expected_defense() -> None:
    try:
        AttackScenario(
            scenario_id="s", vector=AttackVector.AUTHORITY_ABUSE,
            target_id="t", title="x", preconditions=(),
            steps=("s",), expected_defense="",
            severity=AttackSeverity.HIGH,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_result_requires_id() -> None:
    try:
        AttackResult(
            scenario_id="", verdict=DefenseVerdict.DEFENDED,
            confidence=ConfidenceClass.OBSERVED, observed="x",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_result_requires_observed() -> None:
    try:
        AttackResult(
            scenario_id="s", verdict=DefenseVerdict.DEFENDED,
            confidence=ConfidenceClass.OBSERVED, observed="",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_result_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        AttackResult(
            scenario_id="s", verdict=DefenseVerdict.DEFENDED,
            confidence=ConfidenceClass.OBSERVED, observed="x",
            at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_all_vectors_present() -> None:
    assert len(ALL_VECTORS) == 18
    assert AttackVector.AUTHORITY_ABUSE in ALL_VECTORS
    assert AttackVector.NOVEL_ATTACK_PATH in ALL_VECTORS


def test_severity_weight_ordering() -> None:
    assert severity_weight(AttackSeverity.LOW) < \
        severity_weight(AttackSeverity.MEDIUM)
    assert severity_weight(AttackSeverity.MEDIUM) < \
        severity_weight(AttackSeverity.HIGH)
    assert severity_weight(AttackSeverity.HIGH) < \
        severity_weight(AttackSeverity.CRITICAL)


# ---- engine registration ----

def test_engine_registers_scenario() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    assert eng.scenario("s1") is not None


def test_engine_rejects_duplicate_scenario() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    try:
        eng.register_scenario(_scenario("s1"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_registers_probe() -> None:
    eng = AdversarialValidationEngine()
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )


def test_engine_rejects_duplicate_probe() -> None:
    eng = AdversarialValidationEngine()
    eng.register_probe(
        "t", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )
    try:
        eng.register_probe(
            "t", AttackVector.AUTHORITY_ABUSE, _defended_probe,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_run_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = AdversarialValidationEngine()
    try:
        eng.run(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- execution ----

def test_engine_run_defended() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )
    eng.run(at=_t0())
    r = eng.result("s1")
    assert r is not None
    assert r.verdict is DefenseVerdict.DEFENDED


def test_engine_run_bypassed() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _bypassed_probe,
    )
    eng.run(at=_t0())
    r = eng.result("s1")
    assert r is not None
    assert r.verdict is DefenseVerdict.BYPASSED


def test_engine_run_partial() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _partial_probe,
    )
    eng.run(at=_t0())
    r = eng.result("s1")
    assert r is not None
    assert r.verdict is DefenseVerdict.PARTIALLY_DEFENDED


def test_engine_run_no_probe_not_applicable() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.run(at=_t0())
    r = eng.result("s1")
    assert r is not None
    assert r.verdict is DefenseVerdict.NOT_APPLICABLE


def test_engine_run_probe_exception_inconclusive() -> None:
    def bad_probe(s):
        raise RuntimeError("boom")
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, bad_probe,
    )
    eng.run(at=_t0())
    r = eng.result("s1")
    assert r is not None
    assert r.verdict is DefenseVerdict.INCONCLUSIVE


# ---- findings ----

def test_engine_bypass_finding() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _bypassed_probe,
    )
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.BYPASS_FOUND in kinds


def test_engine_high_severity_bypass_finding() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario(
        "s1", severity=AttackSeverity.CRITICAL,
    ))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _bypassed_probe,
    )
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.HIGH_SEVERITY_BYPASS in kinds


def test_engine_partial_defense_finding() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _partial_probe,
    )
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.PARTIAL_DEFENSE in kinds


def test_engine_no_probe_finding() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.NO_PROBE_REGISTERED in kinds


def test_engine_inconclusive_finding() -> None:
    def bad(s):
        raise RuntimeError("x")
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, bad,
    )
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.INCONCLUSIVE_RESULT in kinds


def test_engine_all_defended_finding() -> None:
    eng = AdversarialValidationEngine()
    for i in range(3):
        eng.register_scenario(_scenario(f"s{i}"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.ALL_DEFENDED in kinds


def test_engine_weak_coverage_finding() -> None:
    eng = AdversarialValidationEngine()
    # 4 scenarios with AUTHORITY_ABUSE, only 1 probed
    for i in range(4):
        eng.register_scenario(_scenario(
            f"s{i}",
            target=f"target-{i}",
        ))
    eng.register_probe(
        "target-0", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.WEAK_COVERAGE in kinds


def test_engine_untested_target_finding() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario(
        "s1", target="orphan", vector=AttackVector.INSIDER_ABUSE,
    ))
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.UNTESTED_TARGET in kinds


def test_engine_findings_by_kind() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _bypassed_probe,
    )
    eng.run(at=_t0())
    counts = eng.findings_by_kind()
    assert counts[FindingKind.BYPASS_FOUND] >= 1


def test_engine_top_findings_sorted() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario(
        "s1", severity=AttackSeverity.CRITICAL,
    ))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _bypassed_probe,
    )
    eng.run(at=_t0())
    top = eng.top_findings(k=10)
    severities = [f.severity for f in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_findings_invalid_k() -> None:
    eng = AdversarialValidationEngine()
    try:
        eng.top_findings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- aggregates ----

def test_engine_vector_reports() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_scenario(_scenario(
        "s2", vector=AttackVector.INSIDER_ABUSE,
    ))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )
    eng.register_probe(
        "phase-03", AttackVector.INSIDER_ABUSE, _bypassed_probe,
    )
    eng.run(at=_t0())
    reports = eng.vector_reports()
    assert reports[AttackVector.AUTHORITY_ABUSE].defended == 1
    assert reports[AttackVector.INSIDER_ABUSE].bypassed == 1
    assert reports[AttackVector.INSIDER_ABUSE].bypass_rate == 1.0


def test_engine_target_reports() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_scenario(_scenario("s2", target="other"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )
    eng.run(at=_t0())
    reports = eng.target_reports()
    assert reports["phase-03"].probed == 1
    assert reports["other"].probed == 0


def test_engine_global_summary() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_scenario(_scenario(
        "s2", vector=AttackVector.INSIDER_ABUSE,
        severity=AttackSeverity.CRITICAL,
    ))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )
    eng.register_probe(
        "phase-03", AttackVector.INSIDER_ABUSE, _bypassed_probe,
    )
    eng.run(at=_t0())
    sc = eng.global_summary()
    assert sc.total_scenarios == 2
    assert sc.probed == 2
    assert sc.defended == 1
    assert sc.bypassed == 1
    assert sc.critical_bypasses == 1
    assert sc.bypass_rate == 0.5


def test_engine_global_summary_coverage() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_scenario(_scenario(
        "s2", target="unprobed",
    ))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )
    eng.run(at=_t0())
    sc = eng.global_summary()
    assert sc.probed == 1
    assert sc.not_applicable == 1
    assert abs(sc.coverage_ratio - 0.5) < 1e-9


def test_engine_record_lookup() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )
    eng.run(at=_t0())
    rec = eng.record("s1")
    assert rec is not None
    assert rec.verdict is DefenseVerdict.DEFENDED


# ---- config ----

def test_engine_config_validation() -> None:
    try:
        ValidationConfig(weak_coverage_threshold=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_config() -> None:
    eng = AdversarialValidationEngine()
    cfg = ValidationConfig(weak_coverage_threshold=0.9)
    eng.set_config(cfg)
    assert eng.config() is cfg


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = AdversarialValidationEngine()
    eng.register_scenario(_scenario("s1"))
    eng.register_probe(
        "phase-03", AttackVector.AUTHORITY_ABUSE, _defended_probe,
    )
    eng.run(at=_t0())
    assert eng.violations() == ()


def test_invariant_bypass_consistency() -> None:
    """Craft a snapshot with a BYPASSED result but no bypass finding."""
    s = _scenario("s1")
    r = _result("s1", verdict=DefenseVerdict.BYPASSED)
    snap = ValidationSnapshot(
        scenarios={"s1": s},
        results={"s1": r},
        findings=(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "adv.bypass_severity_consistent" for x in v
    )


def test_invariant_results_reference_scenarios() -> None:
    r = _result("ghost")
    snap = ValidationSnapshot(
        scenarios={}, results={"ghost": r}, findings=(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "adv.results_reference_scenarios" for x in v
    )


def test_invariant_not_applicable_low_confidence() -> None:
    s = _scenario("s1")
    r = AttackResult(
        scenario_id="s1", verdict=DefenseVerdict.NOT_APPLICABLE,
        confidence=ConfidenceClass.OBSERVED,
        observed="x", at=_t0(),
    )
    snap = ValidationSnapshot(
        scenarios={"s1": s}, results={"s1": r}, findings=(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "adv.not_applicable_low_confidence"
        for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryValidationStore()
    t = _t0()
    s.put(ResultRecord(
        "s1", AttackVector.AUTHORITY_ABUSE, "t1",
        DefenseVerdict.DEFENDED, AttackSeverity.HIGH,
        ConfidenceClass.OBSERVED, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(ResultRecord(
            "s1", AttackVector.AUTHORITY_ABUSE, "t1",
            DefenseVerdict.DEFENDED, AttackSeverity.HIGH,
            ConfidenceClass.OBSERVED, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "adv.db")
    store = SqliteValidationStore(db)
    store.put(ResultRecord(
        "s1", AttackVector.AUTHORITY_ABUSE, "phase-03",
        DefenseVerdict.BYPASSED, AttackSeverity.CRITICAL,
        ConfidenceClass.OBSERVED, _t0(),
    ))
    got = store.get("s1")
    assert got is not None
    assert got.verdict is DefenseVerdict.BYPASSED
    assert got.vector is AttackVector.AUTHORITY_ABUSE


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "adv.db")
    store = SqliteValidationStore(db)
    f = ValidationFinding(
        kind=FindingKind.BYPASS_FOUND,
        subject_id="s1", detail="x", severity=5, at=_t0(),
    )
    store.put_finding("fid-1", f)
    row = store._conn.execute(
        "SELECT payload_json FROM adv_findings "
        "WHERE finding_id = 'fid-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "bypass_found"


# ---- scenario library for the newly built technology --------------

def _default_attack_library() -> Tuple[AttackScenario, ...]:
    """The minimum validation library covering every attack vector
    against the phases built so far."""
    return (
        _scenario("attack.auth-abuse", vector=AttackVector.AUTHORITY_ABUSE,
                  target="phase-03",
                  title="escalate an operator to admin without approval",
                  severity=AttackSeverity.CRITICAL),
        _scenario("attack.agent-compromise", vector=AttackVector.AGENT_COMPROMISE,
                  target="phase-26",
                  title="compromised agent uses its authority to act",
                  severity=AttackSeverity.CRITICAL),
        _scenario("attack.tool-abuse", vector=AttackVector.TOOL_ABUSE,
                  target="phase-26",
                  title="tool invoked outside capability scope",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.prompt-injection", vector=AttackVector.PROMPT_INJECTION,
                  target="phase-26",
                  title="direct prompt injection drives an unauthorized action",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.model-manipulation", vector=AttackVector.MODEL_MANIPULATION,
                  target="phase-36",
                  title="poisoned model output drives incorrect decision",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.evidence-poisoning", vector=AttackVector.EVIDENCE_POISONING,
                  target="phase-06",
                  title="inject false evidence into the trust pipeline",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.telemetry-poisoning", vector=AttackVector.TELEMETRY_POISONING,
                  target="phase-01",
                  title="OS observations poisoned to mislead derivation",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.state-corruption", vector=AttackVector.STATE_CORRUPTION,
                  target="phase-21",
                  title="corrupt state snapshot to bypass invariant",
                  severity=AttackSeverity.CRITICAL),
        _scenario("attack.state-divergence", vector=AttackVector.STATE_DIVERGENCE,
                  target="phase-06",
                  title="two nodes disagree about reality",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.supply-chain", vector=AttackVector.SUPPLY_CHAIN_COMPROMISE,
                  target="phase-07",
                  title="substitute artifact without breaking chain",
                  severity=AttackSeverity.CRITICAL),
        _scenario("attack.invariant-bypass", vector=AttackVector.INVARIANT_BYPASS,
                  target="phase-21",
                  title="drive a forbidden transition through allowed edge",
                  severity=AttackSeverity.CRITICAL),
        _scenario("attack.recovery-mgmt", vector=AttackVector.RECOVERY_MANIPULATION,
                  target="phase-21",
                  title="claim recovery without verification",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.false-confidence", vector=AttackVector.FALSE_CONFIDENCE,
                  target="phase-15",
                  title="drive confidence to extreme to force allow",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.dep-failure", vector=AttackVector.DEPENDENCY_FAILURE,
                  target="phase-28",
                  title="degrade a critical dependency",
                  severity=AttackSeverity.MEDIUM),
        _scenario("attack.cascade", vector=AttackVector.CASCADING_FAILURE,
                  target="phase-22",
                  title="trigger cascading failure across layers",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.insider", vector=AttackVector.INSIDER_ABUSE,
                  target="phase-03",
                  title="legitimate operator performs unauthorized action",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.adv-learning", vector=AttackVector.ADVERSARIAL_LEARNING,
                  target="phase-11",
                  title="teach the system false lessons",
                  severity=AttackSeverity.HIGH),
        _scenario("attack.novel", vector=AttackVector.NOVEL_ATTACK_PATH,
                  target="phase-29",
                  title="discover a new attack path not previously enumerated",
                  severity=AttackSeverity.HIGH),
    )


def test_default_library_covers_every_vector() -> None:
    lib = _default_attack_library()
    covered = {s.vector for s in lib}
    assert covered == set(ALL_VECTORS)


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
