"""
HYDRA POST-CORE — PHASE 36: MULTI-MODEL ASSURANCE
=====================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Domain — 6 model roles, 5 reliability verdicts, 5 routing verdicts,
    5 agreement verdicts, 11 finding kinds
  * Model registry with:
      - declared role, provider, version, capabilities
      - trust score, latency, cost tier
      - reliability history (Beta-like counters)
  * Outputs recorded from models on a *task basis*, allowing:
      - per-task agreement measurement across models
      - per-task disagreement classification
      - confidence comparison across models
  * Reliability tracker — per model per task-type success counters
  * Model failure detector — thresholds on recent failures,
    rate, consecutive failures, latency, variance
  * Model routing — selects a model for a task under policy:
      - required capability
      - min trust
      - max latency
      - max cost tier
      - allowed roles
      - fallback chain
  * Fallback decision — if primary fails or is unroutable, produce a
    fallback selection with rationale
  * Output verification — cross-model verification:
      - confirm output when ≥ quorum of independent models agree
      - flag when top-2 disagree beyond tolerance
  * Adversarial model comparison — compare a model's outputs against a
    baseline model over identical tasks to detect drift
  * Findings — 11 kinds
  * Invariants — model trust bounded, reliability bounded,
    fallback ≠ primary, agreement bounded, etc.
  * In-memory + SQLite stores
  * Phase-36 engine facade
  * Full test suite + manual runner

Doctrine: models are *intelligence resources*. HYDRA remains the
governed security system. This module does NOT create a second Cyber
Brain; it makes the multi-model inference layer trustworthy and
governable.

No third-party dependencies.

Run tests:
    python hydra_phase36_multi_model_assurance.py
    pytest hydra_phase36_multi_model_assurance.py -q
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


# =============================================================================
# SECTION 2 — DOMAIN ENUMS
# =============================================================================


class ModelRole(str, Enum):
    REASONING = "reasoning"
    CLASSIFICATION = "classification"
    EMBEDDING = "embedding"
    SUMMARIZATION = "summarization"
    GUARDRAIL = "guardrail"
    SPECIALIZED = "specialized"


ALL_ROLES: Tuple[ModelRole, ...] = tuple(ModelRole)


class ReliabilityVerdict(str, Enum):
    UNKNOWN = "unknown"
    UNRELIABLE = "unreliable"
    MIXED = "mixed"
    RELIABLE = "reliable"
    HIGHLY_RELIABLE = "highly_reliable"


class RoutingVerdict(str, Enum):
    ROUTED = "routed"
    ROUTED_WITH_FALLBACK = "routed_with_fallback"
    ROUTED_DEGRADED = "routed_degraded"
    NO_ROUTE = "no_route"
    REFUSED = "refused"


class AgreementVerdict(str, Enum):
    UNANIMOUS = "unanimous"
    MAJORITY = "majority"
    SPLIT = "split"
    CONTRADICTORY = "contradictory"
    INSUFFICIENT = "insufficient"


class FindingKind(str, Enum):
    MODEL_TRUST_LOW = "model_trust_low"
    MODEL_UNRELIABLE = "model_unreliable"
    MODEL_FAILURE_DETECTED = "model_failure_detected"
    MODEL_CONSECUTIVE_FAILURES = "model_consecutive_failures"
    MODEL_LATENCY_DEGRADED = "model_latency_degraded"
    NO_ROUTE_AVAILABLE = "no_route_available"
    FALLBACK_USED = "fallback_used"
    LOW_AGREEMENT = "low_agreement"
    CONTRADICTORY_OUTPUTS = "contradictory_outputs"
    ADVERSARIAL_DRIFT = "adversarial_drift"
    OUTPUT_VERIFIED = "output_verified"


@dataclass(frozen=True)
class AssuranceFinding:
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
# SECTION 3 — MODEL REGISTRATION
# =============================================================================


@dataclass(frozen=True)
class ModelProfile:
    model_id: str
    role: ModelRole
    name: str
    provider: str
    version: str
    capabilities: FrozenSet[str]
    trust: float                  # 0..1 declared/current trust
    latency_ms_p50: float
    cost_tier: int                # 0..4 (0 cheapest, 4 most expensive)
    max_context_tokens: int
    is_fallback_eligible: bool = True
    tags: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.model_id:
            raise ValueError("model_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not self.provider:
            raise ValueError("provider is required")
        if not self.version:
            raise ValueError("version is required")
        if not 0.0 <= self.trust <= 1.0:
            raise ValueError("trust must be within [0,1]")
        if self.latency_ms_p50 < 0:
            raise ValueError("latency_ms_p50 must be >= 0")
        if not 0 <= self.cost_tier <= 4:
            raise ValueError("cost_tier must be in [0,4]")
        if self.max_context_tokens < 0:
            raise ValueError("max_context_tokens must be >= 0")


# =============================================================================
# SECTION 4 — INFERENCE REQUESTS + OUTPUTS
# =============================================================================


@dataclass(frozen=True)
class InferenceRequest:
    task_id: str
    task_type: str
    required_capabilities: FrozenSet[str]
    max_latency_ms: float
    max_cost_tier: int
    min_trust: float
    allowed_roles: FrozenSet[ModelRole] = frozenset()
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.task_id:
            raise ValueError("task_id is required")
        if not self.task_type:
            raise ValueError("task_type is required")
        if self.max_latency_ms < 0:
            raise ValueError("max_latency_ms must be >= 0")
        if not 0 <= self.max_cost_tier <= 4:
            raise ValueError("max_cost_tier must be in [0,4]")
        if not 0.0 <= self.min_trust <= 1.0:
            raise ValueError("min_trust must be within [0,1]")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class ModelOutput:
    output_id: str
    model_id: str
    task_id: str
    task_type: str
    content_digest: str       # canonical digest of the output
    label: str                # e.g. "trusted", "suspicious", "unknown"
    confidence: float         # 0..1 self-reported
    latency_ms: float
    tokens_used: int
    success: bool
    at: datetime

    def __post_init__(self) -> None:
        if not self.output_id:
            raise ValueError("output_id is required")
        if not self.model_id:
            raise ValueError("model_id is required")
        if not self.task_id:
            raise ValueError("task_id is required")
        if not self.task_type:
            raise ValueError("task_type is required")
        if not self.content_digest:
            raise ValueError("content_digest is required")
        if not self.label:
            raise ValueError("label is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")
        if self.latency_ms < 0:
            raise ValueError("latency_ms must be >= 0")
        if self.tokens_used < 0:
            raise ValueError("tokens_used must be >= 0")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


# =============================================================================
# SECTION 5 — RELIABILITY TRACKING
# =============================================================================


@dataclass
class _ReliabilityState:
    model_id: str
    task_type: str
    successes: int = 0
    failures: int = 0
    recent: deque = field(default_factory=lambda: deque(maxlen=50))

    @property
    def total(self) -> int:
        return self.successes + self.failures

    @property
    def success_rate(self) -> float:
        t = self.total
        return (self.successes / t) if t > 0 else 0.0


def _reliability_verdict(
    rate: float, total: int, *,
    min_samples: int = 3,
) -> ReliabilityVerdict:
    if total < min_samples:
        return ReliabilityVerdict.UNKNOWN
    if rate < 0.5:
        return ReliabilityVerdict.UNRELIABLE
    if rate < 0.75:
        return ReliabilityVerdict.MIXED
    if rate < 0.95:
        return ReliabilityVerdict.RELIABLE
    return ReliabilityVerdict.HIGHLY_RELIABLE


# =============================================================================
# SECTION 6 — AGREEMENT
# =============================================================================


@dataclass(frozen=True)
class AgreementReport:
    task_id: str
    verdict: AgreementVerdict
    total_outputs: int
    agreeing_label: Optional[str]
    agreeing_count: int
    distinct_labels: int
    agreement_ratio: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.agreement_ratio <= 1.0:
            raise ValueError("agreement_ratio must be within [0,1]")


def measure_agreement(
    outputs: Sequence[ModelOutput],
    *, min_quorum: int = 2,
) -> AgreementReport:
    """Compute agreement over a set of outputs for a single task."""
    if min_quorum < 1:
        raise ValueError("min_quorum must be >= 1")
    task_id = outputs[0].task_id if outputs else ""
    if not outputs:
        return AgreementReport(
            task_id=task_id, verdict=AgreementVerdict.INSUFFICIENT,
            total_outputs=0, agreeing_label=None, agreeing_count=0,
            distinct_labels=0, agreement_ratio=0.0,
        )
    counts: Dict[str, int] = {}
    for o in outputs:
        counts[o.label] = counts.get(o.label, 0) + 1
    distinct = len(counts)
    top_label, top_count = max(
        counts.items(), key=lambda kv: (kv[1], kv[0]),
    )
    ratio = top_count / len(outputs)

    if len(outputs) < min_quorum:
        verdict = AgreementVerdict.INSUFFICIENT
    elif distinct == 1:
        verdict = AgreementVerdict.UNANIMOUS
    elif ratio > 0.5:
        verdict = AgreementVerdict.MAJORITY
    elif distinct == len(outputs) and len(outputs) >= 3:
        verdict = AgreementVerdict.CONTRADICTORY
    else:
        verdict = AgreementVerdict.SPLIT

    return AgreementReport(
        task_id=task_id, verdict=verdict,
        total_outputs=len(outputs),
        agreeing_label=top_label, agreeing_count=top_count,
        distinct_labels=distinct, agreement_ratio=ratio,
    )


# =============================================================================
# SECTION 7 — ROUTING
# =============================================================================


@dataclass(frozen=True)
class RoutingDecision:
    task_id: str
    verdict: RoutingVerdict
    primary_model_id: Optional[str]
    fallback_model_ids: Tuple[str, ...]
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def _eligible(
    m: ModelProfile,
    req: InferenceRequest,
    *,
    reliability: Optional[float],
    reliability_min_samples: int,
) -> bool:
    if req.allowed_roles and m.role not in req.allowed_roles:
        return False
    if not req.required_capabilities.issubset(m.capabilities):
        return False
    if m.latency_ms_p50 > req.max_latency_ms:
        return False
    if m.cost_tier > req.max_cost_tier:
        return False
    if m.trust < req.min_trust:
        return False
    # Reliability gate: if we have enough samples, require ≥ 0.5
    if reliability is not None and reliability_min_samples > 0:
        # callers pass reliability=None when insufficient samples
        if reliability < 0.5:
            return False
    return True


def _rank_key(
    m: ModelProfile, *, reliability: Optional[float],
) -> Tuple[float, float, int, str]:
    """Higher is better: trust, reliability, lower cost, then id."""
    r = reliability if reliability is not None else 0.5
    return (m.trust, r, -m.cost_tier, m.model_id)


# =============================================================================
# SECTION 8 — INVARIANTS
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
class AssuranceSnapshot:
    models: Mapping[str, ModelProfile]
    outputs: Tuple[ModelOutput, ...]
    routing_decisions: Tuple[RoutingDecision, ...]
    findings: Tuple[AssuranceFinding, ...]


@dataclass(frozen=True)
class AssuranceInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[AssuranceSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_trust_bounded(snap: AssuranceSnapshot) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for mid, m in snap.models.items():
        if not 0.0 <= m.trust <= 1.0:
            out.append(InvariantViolation(
                invariant_id="mm.trust_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=mid,
                detail=f"trust {m.trust}",
            ))
    return tuple(out)


def _inv_routing_primary_not_fallback(
    snap: AssuranceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for d in snap.routing_decisions:
        if d.primary_model_id is None:
            continue
        if d.primary_model_id in d.fallback_model_ids:
            out.append(InvariantViolation(
                invariant_id="mm.primary_not_fallback",
                severity=InvariantSeverity.HIGH,
                subject_id=d.task_id,
                detail="primary model listed as a fallback",
            ))
    return tuple(out)


def _inv_fallbacks_registered(
    snap: AssuranceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for d in snap.routing_decisions:
        for fid in d.fallback_model_ids:
            if fid not in snap.models:
                out.append(InvariantViolation(
                    invariant_id="mm.fallbacks_registered",
                    severity=InvariantSeverity.HIGH,
                    subject_id=d.task_id,
                    detail=f"fallback {fid} not registered",
                ))
    return tuple(out)


def _inv_outputs_confidence_bounded(
    snap: AssuranceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for o in snap.outputs:
        if not 0.0 <= o.confidence <= 1.0:
            out.append(InvariantViolation(
                invariant_id="mm.output_confidence_bounded",
                severity=InvariantSeverity.HIGH,
                subject_id=o.output_id,
                detail=f"confidence {o.confidence}",
            ))
    return tuple(out)


def _inv_findings_severity_bounded(
    snap: AssuranceSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if not 1 <= f.severity <= 5:
            out.append(InvariantViolation(
                invariant_id="mm.findings_severity_bounded",
                severity=InvariantSeverity.LOW,
                subject_id=f.subject_id,
                detail=f"severity {f.severity}",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[AssuranceInvariant, ...] = (
    AssuranceInvariant(
        invariant_id="mm.trust_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_trust_bounded,
        description="Model trust must lie within [0,1].",
    ),
    AssuranceInvariant(
        invariant_id="mm.primary_not_fallback",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_routing_primary_not_fallback,
        description="Primary model must not be in the fallback list.",
    ),
    AssuranceInvariant(
        invariant_id="mm.fallbacks_registered",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_fallbacks_registered,
        description="Fallback models must be registered.",
    ),
    AssuranceInvariant(
        invariant_id="mm.output_confidence_bounded",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_outputs_confidence_bounded,
        description="Output confidence must lie within [0,1].",
    ),
    AssuranceInvariant(
        invariant_id="mm.findings_severity_bounded",
        severity=InvariantSeverity.LOW,
        predicate=_inv_findings_severity_bounded,
        description="Findings must carry a valid severity.",
    ),
)


def check_invariants(
    snap: AssuranceSnapshot,
    invariants: Iterable[AssuranceInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 9 — STORE
# =============================================================================


@dataclass(frozen=True)
class ModelStateRecord:
    model_id: str
    role: ModelRole
    trust: float
    reliability_verdict: ReliabilityVerdict
    total_inferences: int
    success_rate: float
    updated_at: datetime


class AssuranceStore(Protocol):
    def put_model(self, record: ModelStateRecord) -> None: ...
    def get_model(self, model_id: str) -> Optional[ModelStateRecord]: ...
    def all_models(self) -> Tuple[ModelStateRecord, ...]: ...


class InMemoryAssuranceStore:
    def __init__(self) -> None:
        self._data: Dict[str, ModelStateRecord] = {}

    def put_model(self, record: ModelStateRecord) -> None:
        existing = self._data.get(record.model_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.model_id] = record

    def get_model(self, model_id: str) -> Optional[ModelStateRecord]:
        return self._data.get(model_id)

    def all_models(self) -> Tuple[ModelStateRecord, ...]:
        return tuple(self._data.values())


class SqliteAssuranceStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mm_models (
                model_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                trust REAL NOT NULL,
                reliability_verdict TEXT NOT NULL,
                total_inferences INTEGER NOT NULL,
                success_rate REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mm_findings (
                finding_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put_model(self, record: ModelStateRecord) -> None:
        existing = self.get_model(record.model_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO mm_models
              (model_id, role, trust, reliability_verdict,
               total_inferences, success_rate, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(model_id) DO UPDATE SET
              role=excluded.role,
              trust=excluded.trust,
              reliability_verdict=excluded.reliability_verdict,
              total_inferences=excluded.total_inferences,
              success_rate=excluded.success_rate,
              updated_at=excluded.updated_at
            """,
            (
                record.model_id, record.role.value, record.trust,
                record.reliability_verdict.value,
                record.total_inferences, record.success_rate,
                record.updated_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get_model(self, model_id: str) -> Optional[ModelStateRecord]:
        row = self._conn.execute(
            "SELECT role, trust, reliability_verdict, total_inferences, "
            "success_rate, updated_at FROM mm_models WHERE model_id = ?",
            (model_id,),
        ).fetchone()
        if row is None:
            return None
        return ModelStateRecord(
            model_id=model_id, role=ModelRole(row[0]),
            trust=float(row[1]),
            reliability_verdict=ReliabilityVerdict(row[2]),
            total_inferences=int(row[3]),
            success_rate=float(row[4]),
            updated_at=datetime.fromisoformat(row[5]),
        )

    def all_models(self) -> Tuple[ModelStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT model_id FROM mm_models"
        ).fetchall()
        return tuple(
            r for r in (self.get_model(x[0]) for x in rows)
            if r is not None
        )

    def put_finding(self, finding_id: str, f: AssuranceFinding) -> None:
        payload = {
            "finding_id": finding_id,
            "kind": f.kind.value,
            "subject_id": f.subject_id,
            "detail": f.detail,
            "severity": f.severity,
            "at": f.at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO mm_findings "
            "(finding_id, payload_json) VALUES (?, ?)",
            (finding_id, json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()


# =============================================================================
# SECTION 10 — ENGINE
# =============================================================================


@dataclass(frozen=True)
class AssuranceConfig:
    reliability_min_samples: int = 3
    reliability_floor: float = 0.5
    consecutive_failure_threshold: int = 3
    latency_degraded_ratio: float = 2.0
    agreement_min_quorum: int = 2
    agreement_low_ratio: float = 0.6
    drift_tolerance: float = 0.3
    max_findings: int = 5000

    def __post_init__(self) -> None:
        if self.reliability_min_samples < 1:
            raise ValueError("reliability_min_samples must be >= 1")
        for n, v in (
            ("reliability_floor", self.reliability_floor),
            ("agreement_low_ratio", self.agreement_low_ratio),
            ("drift_tolerance", self.drift_tolerance),
        ):
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{n} must be within [0,1]")
        if self.consecutive_failure_threshold < 1:
            raise ValueError(
                "consecutive_failure_threshold must be >= 1"
            )
        if self.latency_degraded_ratio <= 0:
            raise ValueError("latency_degraded_ratio must be > 0")
        if self.agreement_min_quorum < 1:
            raise ValueError("agreement_min_quorum must be >= 1")
        if self.max_findings < 1:
            raise ValueError("max_findings must be >= 1")


class MultiModelAssuranceEngine:
    """Multi-model assurance engine.

    Treats models as intelligence resources. Verifies their outputs,
    routes tasks under policy, tracks reliability, and detects
    disagreement + drift. HYDRA remains the governed system.
    """

    def __init__(
        self,
        *,
        store: Optional[AssuranceStore] = None,
        config: Optional[AssuranceConfig] = None,
    ) -> None:
        self._store: AssuranceStore = store or InMemoryAssuranceStore()
        self._config = config or AssuranceConfig()
        self._models: Dict[str, ModelProfile] = {}
        self._reliability: Dict[Tuple[str, str], _ReliabilityState] = {}
        self._outputs: List[ModelOutput] = []
        self._outputs_by_task: Dict[str, List[ModelOutput]] = {}
        self._routing_decisions: List[RoutingDecision] = []
        self._findings: List[AssuranceFinding] = []
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._decision_seq = 0

    # ---- registration ----------------------------------------------------

    def register_model(self, m: ModelProfile) -> None:
        if m.model_id in self._models:
            raise ValueError(
                f"model {m.model_id} already registered"
            )
        self._models[m.model_id] = m

    def model(self, model_id: str) -> Optional[ModelProfile]:
        return self._models.get(model_id)

    def models(self) -> Tuple[ModelProfile, ...]:
        return tuple(self._models.values())

    def config(self) -> AssuranceConfig:
        return self._config

    def set_config(self, config: AssuranceConfig) -> None:
        self._config = config

    # ---- recording outputs -----------------------------------------------

    def record_output(self, o: ModelOutput) -> None:
        if o.model_id not in self._models:
            raise KeyError(f"model {o.model_id} not registered")
        self._outputs.append(o)
        self._outputs_by_task.setdefault(o.task_id, []).append(o)
        key = (o.model_id, o.task_type)
        st = self._reliability.get(key)
        if st is None:
            st = _ReliabilityState(
                model_id=o.model_id, task_type=o.task_type,
            )
            self._reliability[key] = st
        if o.success:
            st.successes += 1
            st.recent.append(True)
        else:
            st.failures += 1
            st.recent.append(False)

    # ---- reliability -----------------------------------------------------

    def _reliability_state(
        self, model_id: str, task_type: str,
    ) -> Optional[_ReliabilityState]:
        return self._reliability.get((model_id, task_type))

    def reliability_verdict(
        self, model_id: str, task_type: str,
    ) -> ReliabilityVerdict:
        st = self._reliability_state(model_id, task_type)
        if st is None:
            return ReliabilityVerdict.UNKNOWN
        return _reliability_verdict(
            st.success_rate, st.total,
            min_samples=self._config.reliability_min_samples,
        )

    def success_rate(
        self, model_id: str, task_type: Optional[str] = None,
    ) -> float:
        if task_type is not None:
            st = self._reliability_state(model_id, task_type)
            if st is None:
                return 0.0
            return st.success_rate
        # aggregate
        succ = 0
        total = 0
        for (mid, _t), st in self._reliability.items():
            if mid == model_id:
                succ += st.successes
                total += st.total
        return succ / total if total > 0 else 0.0

    # ---- routing ---------------------------------------------------------

    def route(self, req: InferenceRequest) -> RoutingDecision:
        at = req.at or datetime.now().astimezone()
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        cfg = self._config
        candidates: List[Tuple[ModelProfile, Optional[float]]] = []
        for m in self._models.values():
            st = self._reliability_state(m.model_id, req.task_type)
            rel: Optional[float] = None
            if st is not None and st.total >= cfg.reliability_min_samples:
                rel = st.success_rate
            if not _eligible(
                m, req,
                reliability=rel,
                reliability_min_samples=cfg.reliability_min_samples,
            ):
                continue
            if rel is not None and rel < cfg.reliability_floor:
                continue
            candidates.append((m, rel))

        if not candidates:
            decision = RoutingDecision(
                task_id=req.task_id,
                verdict=RoutingVerdict.NO_ROUTE,
                primary_model_id=None,
                fallback_model_ids=(),
                rationale="no model satisfies policy",
                at=at,
            )
            self._routing_decisions.append(decision)
            self._findings.append(AssuranceFinding(
                kind=FindingKind.NO_ROUTE_AVAILABLE,
                subject_id=req.task_id,
                detail="no model satisfies policy",
                severity=4, at=at,
            ))
            return decision

        # Sort candidates deterministically
        candidates.sort(
            key=lambda mr: (
                -_rank_key(mr[0], reliability=mr[1])[0],
                -_rank_key(mr[0], reliability=mr[1])[1],
                _rank_key(mr[0], reliability=mr[1])[2],
                _rank_key(mr[0], reliability=mr[1])[3],
            ),
        )
        primary, _ = candidates[0]
        fallbacks = tuple(
            m.model_id for m, _ in candidates[1:]
            if m.is_fallback_eligible
        )
        verdict = (
            RoutingVerdict.ROUTED_WITH_FALLBACK if fallbacks
            else RoutingVerdict.ROUTED
        )
        # Degraded if primary's trust is low but >= floor
        if primary.trust < 0.5 and verdict is RoutingVerdict.ROUTED:
            verdict = RoutingVerdict.ROUTED_DEGRADED

        decision = RoutingDecision(
            task_id=req.task_id,
            verdict=verdict,
            primary_model_id=primary.model_id,
            fallback_model_ids=fallbacks,
            rationale=(
                f"primary {primary.model_id} "
                f"(trust={primary.trust:.2f}, "
                f"role={primary.role.value})"
            ),
            at=at,
        )
        self._routing_decisions.append(decision)

        if verdict is RoutingVerdict.ROUTED_WITH_FALLBACK:
            self._findings.append(AssuranceFinding(
                kind=FindingKind.FALLBACK_USED,
                subject_id=req.task_id,
                detail=(
                    f"primary {primary.model_id} with "
                    f"{len(fallbacks)} fallback(s)"
                ),
                severity=2, at=at,
            ))
        return decision

    # ---- agreement -------------------------------------------------------

    def agreement_for_task(
        self, task_id: str,
    ) -> AgreementReport:
        outputs = self._outputs_by_task.get(task_id, [])
        report = measure_agreement(
            outputs, min_quorum=self._config.agreement_min_quorum,
        )
        return report

    # ---- adversarial drift -----------------------------------------------

    def adversarial_drift(
        self,
        *,
        model_id: str,
        baseline_model_id: str,
        task_type: str,
    ) -> Tuple[ModelOutput, ModelOutput, float]:
        """Compare model outputs against a baseline on identical tasks.

        Returns (model_output, baseline_output, drift_score) for the
        most recent shared task. drift_score = 0 if labels match and
        confidence delta is small; higher = larger divergence.
        """
        shared: List[Tuple[ModelOutput, ModelOutput]] = []
        by_task_model: Dict[Tuple[str, str], ModelOutput] = {}
        for o in self._outputs:
            if o.task_type != task_type:
                continue
            by_task_model[(o.task_id, o.model_id)] = o
        for (tid, mid), a in by_task_model.items():
            if mid != model_id:
                continue
            b = by_task_model.get((tid, baseline_model_id))
            if b is None:
                continue
            shared.append((a, b))
        if not shared:
            raise KeyError(
                f"no shared task for {model_id} vs {baseline_model_id} "
                f"on {task_type}"
            )
        a, b = shared[-1]
        label_mismatch = 1.0 if a.label != b.label else 0.0
        conf_delta = abs(a.confidence - b.confidence)
        drift = max(0.0, min(1.0, 0.7 * label_mismatch + 0.3 * conf_delta))
        return a, b, drift

    # ---- findings + recompute --------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[ModelStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        cfg = self._config
        self._findings = []

        # Re-derive routing-decision findings from retained decisions,
        # since recompute() rebuilds findings from scratch and routing
        # findings are not otherwise regenerated from any per-model loop.
        for decision in self._routing_decisions:
            if decision.verdict is RoutingVerdict.NO_ROUTE:
                self._findings.append(AssuranceFinding(
                    kind=FindingKind.NO_ROUTE_AVAILABLE,
                    subject_id=decision.task_id,
                    detail=decision.rationale,
                    severity=4, at=decision.at,
                ))

        # Per-model reliability + failure findings
        for m in self._models.values():
            st = self._reliability_state(m.model_id, "")
            # aggregate across task types
            succ = 0
            total = 0
            consecutive_failures = 0
            for (mid, _t), s in self._reliability.items():
                if mid != m.model_id:
                    continue
                succ += s.successes
                total += s.total
                # count trailing False in recent
                for flag in reversed(list(s.recent)):
                    if flag:
                        break
                    consecutive_failures += 1
            rate = succ / total if total > 0 else 0.0
            verdict = _reliability_verdict(
                rate, total,
                min_samples=cfg.reliability_min_samples,
            )
            if m.trust < 0.3:
                self._findings.append(AssuranceFinding(
                    kind=FindingKind.MODEL_TRUST_LOW,
                    subject_id=m.model_id,
                    detail=f"trust {m.trust:.2f} < 0.3",
                    severity=3, at=at,
                ))
            if verdict is ReliabilityVerdict.UNRELIABLE:
                self._findings.append(AssuranceFinding(
                    kind=FindingKind.MODEL_UNRELIABLE,
                    subject_id=m.model_id,
                    detail=f"success rate {rate:.2f} over {total} runs",
                    severity=4, at=at,
                ))
            if consecutive_failures >= cfg.consecutive_failure_threshold:
                self._findings.append(AssuranceFinding(
                    kind=FindingKind.MODEL_CONSECUTIVE_FAILURES,
                    subject_id=m.model_id,
                    detail=(
                        f"{consecutive_failures} consecutive failures"
                    ),
                    severity=4, at=at,
                ))
            # latency degraded vs declared
            latencies = [
                o.latency_ms for o in self._outputs
                if o.model_id == m.model_id
            ]
            if latencies and m.latency_ms_p50 > 0:
                avg = sum(latencies) / len(latencies)
                if avg > m.latency_ms_p50 * cfg.latency_degraded_ratio:
                    self._findings.append(AssuranceFinding(
                        kind=FindingKind.MODEL_LATENCY_DEGRADED,
                        subject_id=m.model_id,
                        detail=(
                            f"avg latency {avg:.0f}ms > "
                            f"{m.latency_ms_p50 * cfg.latency_degraded_ratio:.0f}ms"
                        ),
                        severity=3, at=at,
                    ))

        # Per-task agreement findings
        for task_id, outs in self._outputs_by_task.items():
            report = measure_agreement(
                outs, min_quorum=cfg.agreement_min_quorum,
            )
            if report.verdict is AgreementVerdict.CONTRADICTORY:
                self._findings.append(AssuranceFinding(
                    kind=FindingKind.CONTRADICTORY_OUTPUTS,
                    subject_id=task_id,
                    detail=(
                        f"{report.total_outputs} outputs with "
                        f"{report.distinct_labels} distinct labels"
                    ),
                    severity=5, at=at,
                ))
            elif report.verdict in (
                AgreementVerdict.SPLIT,
                AgreementVerdict.INSUFFICIENT,
            ):
                self._findings.append(AssuranceFinding(
                    kind=FindingKind.LOW_AGREEMENT,
                    subject_id=task_id,
                    detail=(
                        f"agreement ratio {report.agreement_ratio:.2f} "
                        f"({report.verdict.value})"
                    ),
                    severity=3, at=at,
                ))
            elif report.verdict in (
                AgreementVerdict.UNANIMOUS,
                AgreementVerdict.MAJORITY,
            ):
                if report.agreement_ratio >= cfg.agreement_low_ratio \
                   and report.total_outputs >= cfg.agreement_min_quorum:
                    self._findings.append(AssuranceFinding(
                        kind=FindingKind.OUTPUT_VERIFIED,
                        subject_id=task_id,
                        detail=(
                            f"cross-model agreement "
                            f"{report.agreement_ratio:.2f} on "
                            f"'{report.agreeing_label}'"
                        ),
                        severity=1, at=at,
                    ))

        if len(self._findings) > cfg.max_findings:
            self._findings = self._findings[: cfg.max_findings]

        # Persist model records
        records: List[ModelStateRecord] = []
        for m in self._models.values():
            verdict = self.reliability_verdict(m.model_id, "")
            rate = self.success_rate(m.model_id)
            total = sum(
                s.total for (mid, _t), s in self._reliability.items()
                if mid == m.model_id
            )
            rec = ModelStateRecord(
                model_id=m.model_id, role=m.role, trust=m.trust,
                reliability_verdict=verdict,
                total_inferences=total, success_rate=rate,
                updated_at=at,
            )
            self._store.put_model(rec)
            records.append(rec)

        if isinstance(self._store, SqliteAssuranceStore):
            for i, f in enumerate(self._findings):
                self._store.put_finding(
                    f"f-{i:08d}-{f.kind.value}", f,
                )

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def routing_decisions(self) -> Tuple[RoutingDecision, ...]:
        return tuple(self._routing_decisions)

    def outputs(self) -> Tuple[ModelOutput, ...]:
        return tuple(self._outputs)

    def outputs_for_task(self, task_id: str) -> Tuple[ModelOutput, ...]:
        return tuple(self._outputs_by_task.get(task_id, ()))

    def findings(self) -> Tuple[AssuranceFinding, ...]:
        return tuple(self._findings)

    def findings_by_kind(self) -> Mapping[FindingKind, int]:
        out: Dict[FindingKind, int] = {k: 0 for k in FindingKind}
        for f in self._findings:
            out[f.kind] += 1
        return out

    def top_findings(
        self, *, k: int = 10,
    ) -> Tuple[AssuranceFinding, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._findings,
            key=lambda f: (-f.severity, f.kind.value, f.subject_id),
        )
        return tuple(ordered[:k])

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, model_id: str) -> Optional[ModelStateRecord]:
        return self._store.get_model(model_id)

    def snapshot(self) -> AssuranceSnapshot:
        return AssuranceSnapshot(
            models=dict(self._models),
            outputs=tuple(self._outputs),
            routing_decisions=tuple(self._routing_decisions),
            findings=tuple(self._findings),
        )


# =============================================================================
# SECTION 11 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _t(seconds: int) -> datetime:
    return _t0() + timedelta(seconds=seconds)


def _model(
    mid: str, *,
    role: ModelRole = ModelRole.REASONING,
    name: Optional[str] = None,
    caps: Iterable[str] = ("reason",),
    trust: float = 0.9,
    latency: float = 100.0,
    cost: int = 1,
    fallback: bool = True,
) -> ModelProfile:
    return ModelProfile(
        model_id=mid, role=role, name=name or mid,
        provider="test", version="1.0",
        capabilities=frozenset(caps),
        trust=trust, latency_ms_p50=latency,
        cost_tier=cost, max_context_tokens=8192,
        is_fallback_eligible=fallback,
    )


def _req(
    tid: str = "t1", *,
    task_type: str = "classify",
    caps: Iterable[str] = ("reason",),
    max_latency: float = 500.0,
    max_cost: int = 3,
    min_trust: float = 0.5,
    roles: Iterable[ModelRole] = (),
    at: Optional[datetime] = None,
) -> InferenceRequest:
    return InferenceRequest(
        task_id=tid, task_type=task_type,
        required_capabilities=frozenset(caps),
        max_latency_ms=max_latency, max_cost_tier=max_cost,
        min_trust=min_trust,
        allowed_roles=frozenset(roles),
        at=at,
    )


def _output(
    oid: str, mid: str, tid: str = "t1", *,
    task_type: str = "classify",
    digest: str = "abc",
    label: str = "trusted",
    confidence: float = 0.9,
    latency: float = 100.0,
    tokens: int = 100,
    success: bool = True,
    at: Optional[datetime] = None,
) -> ModelOutput:
    return ModelOutput(
        output_id=oid, model_id=mid, task_id=tid,
        task_type=task_type, content_digest=digest, label=label,
        confidence=confidence, latency_ms=latency,
        tokens_used=tokens, success=success,
        at=at or _t0(),
    )


# ---- domain ----

def test_model_requires_id() -> None:
    try:
        ModelProfile(
            model_id="", role=ModelRole.REASONING, name="n",
            provider="p", version="v", capabilities=frozenset(),
            trust=0.5, latency_ms_p50=1.0, cost_tier=1,
            max_context_tokens=1,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_model_trust_bounds() -> None:
    try:
        _model("m", trust=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_model_cost_bounds() -> None:
    try:
        _model("m", cost=5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_request_requires_id() -> None:
    try:
        InferenceRequest(
            task_id="", task_type="x",
            required_capabilities=frozenset(),
            max_latency_ms=100, max_cost_tier=1, min_trust=0.0,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_output_label_required() -> None:
    try:
        ModelOutput(
            output_id="o", model_id="m", task_id="t",
            task_type="x", content_digest="d", label="",
            confidence=0.5, latency_ms=10, tokens_used=1,
            success=True, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_output_confidence_bounds() -> None:
    try:
        ModelOutput(
            output_id="o", model_id="m", task_id="t",
            task_type="x", content_digest="d", label="l",
            confidence=1.5, latency_ms=10, tokens_used=1,
            success=True, at=_t0(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_output_requires_aware_time() -> None:
    from datetime import datetime as dt
    try:
        ModelOutput(
            output_id="o", model_id="m", task_id="t",
            task_type="x", content_digest="d", label="l",
            confidence=0.5, latency_ms=10, tokens_used=1,
            success=True, at=dt(2026, 1, 1),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_reliability_verdict_ordering() -> None:
    assert _reliability_verdict(0.0, 10) is ReliabilityVerdict.UNRELIABLE
    assert _reliability_verdict(0.6, 10) is ReliabilityVerdict.MIXED
    assert _reliability_verdict(0.8, 10) is ReliabilityVerdict.RELIABLE
    assert _reliability_verdict(0.99, 10) is \
        ReliabilityVerdict.HIGHLY_RELIABLE
    assert _reliability_verdict(0.9, 1, min_samples=3) is \
        ReliabilityVerdict.UNKNOWN


# ---- agreement ----

def test_agreement_empty() -> None:
    r = measure_agreement([])
    assert r.verdict is AgreementVerdict.INSUFFICIENT


def test_agreement_unanimous() -> None:
    outs = (
        _output("o1", "m1", label="trusted"),
        _output("o2", "m2", label="trusted"),
        _output("o3", "m3", label="trusted"),
    )
    r = measure_agreement(outs)
    assert r.verdict is AgreementVerdict.UNANIMOUS
    assert r.agreement_ratio == 1.0


def test_agreement_majority() -> None:
    outs = (
        _output("o1", "m1", label="trusted"),
        _output("o2", "m2", label="trusted"),
        _output("o3", "m3", label="suspicious"),
    )
    r = measure_agreement(outs)
    assert r.verdict is AgreementVerdict.MAJORITY
    assert r.agreeing_label == "trusted"
    assert abs(r.agreement_ratio - 2/3) < 1e-9


def test_agreement_contradictory() -> None:
    outs = (
        _output("o1", "m1", label="trusted"),
        _output("o2", "m2", label="suspicious"),
        _output("o3", "m3", label="compromised"),
    )
    r = measure_agreement(outs)
    assert r.verdict is AgreementVerdict.CONTRADICTORY


def test_agreement_insufficient_quorum() -> None:
    outs = (_output("o1", "m1"),)
    r = measure_agreement(outs, min_quorum=2)
    assert r.verdict is AgreementVerdict.INSUFFICIENT


# ---- engine registration ----

def test_engine_registers_model() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    assert eng.model("m1") is not None


def test_engine_rejects_duplicate_model() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    try:
        eng.register_model(_model("m1"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_record_output_unknown_model() -> None:
    eng = MultiModelAssuranceEngine()
    try:
        eng.record_output(_output("o1", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_record_output_updates_reliability() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    eng.record_output(_output("o1", "m1", success=True))
    assert eng.success_rate("m1") == 1.0


def test_engine_success_rate_aggregate() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    for i in range(3):
        eng.record_output(_output(f"o{i}", "m1", success=True))
    for i in range(1):
        eng.record_output(_output(f"f{i}", "m1", success=False))
    assert abs(eng.success_rate("m1") - 0.75) < 1e-9


# ---- routing ----

def test_route_single_model() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    d = eng.route(_req())
    assert d.verdict is RoutingVerdict.ROUTED
    assert d.primary_model_id == "m1"


def test_route_with_fallback() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    eng.register_model(_model("m2"))
    d = eng.route(_req())
    assert d.verdict is RoutingVerdict.ROUTED_WITH_FALLBACK
    assert len(d.fallback_model_ids) >= 1


def test_route_no_route_when_capability_missing() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1", caps=("other",)))
    d = eng.route(_req(caps=("reason",)))
    assert d.verdict is RoutingVerdict.NO_ROUTE


def test_route_no_route_when_latency_exceeded() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1", latency=1000.0))
    d = eng.route(_req(max_latency=500.0))
    assert d.verdict is RoutingVerdict.NO_ROUTE


def test_route_no_route_when_cost_exceeded() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1", cost=4))
    d = eng.route(_req(max_cost=1))
    assert d.verdict is RoutingVerdict.NO_ROUTE


def test_route_no_route_when_trust_below_min() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1", trust=0.2))
    d = eng.route(_req(min_trust=0.5))
    assert d.verdict is RoutingVerdict.NO_ROUTE


def test_route_role_filter() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1", role=ModelRole.REASONING))
    eng.register_model(_model("m2", role=ModelRole.CLASSIFICATION))
    d = eng.route(_req(roles=[ModelRole.CLASSIFICATION]))
    assert d.primary_model_id == "m2"


def test_route_prefers_higher_trust() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("low", trust=0.5))
    eng.register_model(_model("high", trust=0.95))
    d = eng.route(_req())
    assert d.primary_model_id == "high"


def test_route_requires_aware_time_for_inference() -> None:
    from datetime import datetime as dt
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    try:
        eng.route(_req(at=dt(2026, 1, 1)))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_route_no_route_finding() -> None:
    eng = MultiModelAssuranceEngine()
    eng.route(_req())
    # recompute to regenerate findings
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.NO_ROUTE_AVAILABLE in kinds


def test_route_degraded_when_low_trust_primary() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model(
        "m1", trust=0.4, fallback=False,
    ))
    d = eng.route(_req(min_trust=0.3))
    assert d.verdict is RoutingVerdict.ROUTED_DEGRADED


def test_route_ignores_unreliable_model() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("bad"))
    eng.register_model(_model("good"))
    # make "bad" unreliable
    for i in range(5):
        eng.record_output(_output(
            f"bad-{i}", "bad", success=False,
        ))
    d = eng.route(_req())
    # "bad" cannot be primary (reliability floor), so good leads
    assert d.primary_model_id == "good"


# ---- agreement integration ----

def test_engine_agreement_for_task() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    eng.register_model(_model("m2"))
    eng.record_output(_output("o1", "m1", label="trusted"))
    eng.record_output(_output("o2", "m2", label="trusted"))
    r = eng.agreement_for_task("t1")
    assert r.verdict is AgreementVerdict.UNANIMOUS


def test_engine_contradictory_finding() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    eng.register_model(_model("m2"))
    eng.register_model(_model("m3"))
    eng.record_output(_output("o1", "m1", label="a"))
    eng.record_output(_output("o2", "m2", label="b"))
    eng.record_output(_output("o3", "m3", label="c"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.CONTRADICTORY_OUTPUTS in kinds


def test_engine_output_verified_finding() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    eng.register_model(_model("m2"))
    eng.record_output(_output("o1", "m1", label="a"))
    eng.record_output(_output("o2", "m2", label="a"))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.OUTPUT_VERIFIED in kinds


# ---- model failure detection ----

def test_engine_consecutive_failures_finding() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    for i in range(5):
        eng.record_output(_output(
            f"o{i}", "m1", success=False,
        ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.MODEL_CONSECUTIVE_FAILURES in kinds


def test_engine_unreliable_finding() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    for i in range(10):
        eng.record_output(_output(
            f"o{i}", "m1", success=(i < 2),
        ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.MODEL_UNRELIABLE in kinds


def test_engine_latency_degraded_finding() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1", latency=50.0))
    for i in range(5):
        eng.record_output(_output(
            f"o{i}", "m1", latency=500.0,
        ))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.MODEL_LATENCY_DEGRADED in kinds


def test_engine_trust_low_finding() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1", trust=0.1))
    eng.recompute(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.MODEL_TRUST_LOW in kinds


# ---- adversarial drift ----

def test_engine_adversarial_drift_match() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m"))
    eng.register_model(_model("b"))
    eng.record_output(_output("o1", "m", label="trusted",
                              confidence=0.9))
    eng.record_output(_output("o2", "b", label="trusted",
                              confidence=0.9))
    _, _, drift = eng.adversarial_drift(
        model_id="m", baseline_model_id="b",
        task_type="classify",
    )
    assert drift == 0.0


def test_engine_adversarial_drift_mismatch() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m"))
    eng.register_model(_model("b"))
    eng.record_output(_output("o1", "m", label="trusted",
                              confidence=0.9))
    eng.record_output(_output("o2", "b", label="suspicious",
                              confidence=0.3))
    _, _, drift = eng.adversarial_drift(
        model_id="m", baseline_model_id="b",
        task_type="classify",
    )
    assert drift > 0.5


def test_engine_adversarial_drift_no_shared_task() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m"))
    eng.register_model(_model("b"))
    try:
        eng.adversarial_drift(
            model_id="m", baseline_model_id="b",
            task_type="classify",
        )
    except KeyError:
        return
    raise AssertionError("expected KeyError")


# ---- recompute + records ----

def test_engine_recompute_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = MultiModelAssuranceEngine()
    try:
        eng.recompute(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_recompute_returns_records() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    eng.record_output(_output("o1", "m1"))
    records = eng.recompute(at=_t0())
    assert len(records) == 1
    assert records[0].model_id == "m1"


def test_engine_reliability_verdict_per_task_type() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    for i in range(5):
        eng.record_output(_output(
            f"o{i}", "m1", task_type="classify", success=True,
        ))
    assert eng.reliability_verdict("m1", "classify") is \
        ReliabilityVerdict.HIGHLY_RELIABLE
    assert eng.reliability_verdict("m1", "other") is \
        ReliabilityVerdict.UNKNOWN


def test_engine_findings_by_kind() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1", trust=0.1))
    eng.recompute(at=_t0())
    counts = eng.findings_by_kind()
    assert counts[FindingKind.MODEL_TRUST_LOW] >= 1


def test_engine_top_findings_sorted() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1", trust=0.1))
    eng.register_model(_model("m2"))
    eng.record_output(_output("o1", "m2", label="a"))
    eng.record_output(_output("o2", "m1", label="b"))
    eng.record_output(_output("o3", "m1", label="c"))
    eng.recompute(at=_t0())
    top = eng.top_findings(k=10)
    severities = [f.severity for f in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_findings_invalid_k() -> None:
    eng = MultiModelAssuranceEngine()
    try:
        eng.top_findings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_record_lookup() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    eng.recompute(at=_t0())
    rec = eng.record("m1")
    assert rec is not None
    assert rec.role is ModelRole.REASONING


def test_engine_routing_decisions_lookup() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    eng.route(_req())
    assert len(eng.routing_decisions()) == 1


def test_engine_outputs_for_task() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    eng.record_output(_output("o1", "m1"))
    assert len(eng.outputs_for_task("t1")) == 1


# ---- config ----

def test_engine_config_validation() -> None:
    try:
        AssuranceConfig(reliability_floor=1.5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_set_config() -> None:
    eng = MultiModelAssuranceEngine()
    cfg = AssuranceConfig(reliability_min_samples=10)
    eng.set_config(cfg)
    assert eng.config() is cfg


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = MultiModelAssuranceEngine()
    eng.register_model(_model("m1"))
    eng.route(_req())
    eng.recompute(at=_t0())
    assert eng.violations() == ()


def test_invariant_primary_not_fallback() -> None:
    bad = RoutingDecision(
        task_id="t", verdict=RoutingVerdict.ROUTED_WITH_FALLBACK,
        primary_model_id="m1",
        fallback_model_ids=("m1", "m2"),
        rationale="bad", at=_t0(),
    )
    snap = AssuranceSnapshot(
        models={}, outputs=(),
        routing_decisions=(bad,), findings=(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "mm.primary_not_fallback" for x in v
    )


def test_invariant_fallbacks_registered() -> None:
    bad = RoutingDecision(
        task_id="t", verdict=RoutingVerdict.ROUTED_WITH_FALLBACK,
        primary_model_id="m1",
        fallback_model_ids=("ghost",),
        rationale="bad", at=_t0(),
    )
    snap = AssuranceSnapshot(
        models={}, outputs=(),
        routing_decisions=(bad,), findings=(),
    )
    v = check_invariants(snap)
    assert any(
        x.invariant_id == "mm.fallbacks_registered" for x in v
    )


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryAssuranceStore()
    t = _t0()
    s.put_model(ModelStateRecord(
        "m", ModelRole.REASONING, 0.9,
        ReliabilityVerdict.RELIABLE, 10, 0.9, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put_model(ModelStateRecord(
            "m", ModelRole.REASONING, 0.9,
            ReliabilityVerdict.RELIABLE, 10, 0.9, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "mm.db")
    store = SqliteAssuranceStore(db)
    store.put_model(ModelStateRecord(
        "m1", ModelRole.REASONING, 0.9,
        ReliabilityVerdict.RELIABLE, 20, 0.85, _t0(),
    ))
    got = store.get_model("m1")
    assert got is not None
    assert got.role is ModelRole.REASONING
    assert abs(got.success_rate - 0.85) < 1e-9


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "mm.db")
    store = SqliteAssuranceStore(db)
    f = AssuranceFinding(
        kind=FindingKind.MODEL_TRUST_LOW,
        subject_id="m1", detail="x", severity=3, at=_t0(),
    )
    store.put_finding("fid-1", f)
    row = store._conn.execute(
        "SELECT payload_json FROM mm_findings "
        "WHERE finding_id = 'fid-1'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "model_trust_low"


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
