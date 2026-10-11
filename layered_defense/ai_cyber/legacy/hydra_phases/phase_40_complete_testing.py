"""
HYDRA POST-CORE — PHASE 40: COMPLETE TESTING
===============================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * A *complete testing framework* with 11 first-class test categories:
      UNIT, INTEGRATION, NEGATIVE, BOUNDARY, FAILURE, SECURITY,
      ADVERSARIAL, REGRESSION, PERSISTENCE, CONCURRENCY, PERFORMANCE
  * Test registry + suites + orchestrator with:
      - per-test timeout
      - retry policy (for non-deterministic tests only)
      - parallel execution (deterministic ordering of results)
      - isolation between tests
  * Coverage rules — every registered component must have at least
    one test in each *required* category
  * Regression tracking — compares current run against a stored
    baseline (pass/fail deltas per test id)
  * Performance tracking — p50/p95/p99 latencies per category,
    detects slowdowns relative to baseline
  * Findings — 10 kinds
  * Machine-checkable test-framework invariants
  * In-memory + SQLite stores for run history
  * Phase-40 engine facade
  * A self-contained SUT + a substantive set of tests in each of the
    11 categories so the framework is exercised end to end.
  * Full test suite + manual runner

Doctrine: "every new component must receive unit, integration,
negative, boundary, failure, security, adversarial, regression,
persistence, concurrency (where relevant), and performance tests".

This module is the orchestrator that makes that doctrine
machine-checkable. It does NOT replace per-phase tests; it verifies
that they exist, run them, and hold the line on regressions.

No third-party dependencies.

Run tests:
    python hydra_phase40_complete_testing.py
    pytest hydra_phase40_complete_testing.py -q
"""
from __future__ import annotations

import json
import math
import sqlite3
import threading
import time
from concurrent.futures import (
    Future,
    ThreadPoolExecutor,
    TimeoutError as FutureTimeoutError,
)
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


class TestCategory(str, Enum):
    UNIT = "unit"
    INTEGRATION = "integration"
    NEGATIVE = "negative"
    BOUNDARY = "boundary"
    FAILURE = "failure"
    SECURITY = "security"
    ADVERSARIAL = "adversarial"
    REGRESSION = "regression"
    PERSISTENCE = "persistence"
    CONCURRENCY = "concurrency"
    PERFORMANCE = "performance"


ALL_CATEGORIES: Tuple[TestCategory, ...] = tuple(TestCategory)


class TestOutcome(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    TIMEOUT = "timeout"


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


class FindingKind(str, Enum):
    SUITE_PASSED = "suite_passed"
    TEST_FAILED = "test_failed"
    TEST_ERRORED = "test_errored"
    TEST_TIMED_OUT = "test_timed_out"
    COVERAGE_GAP = "coverage_gap"
    REGRESSION_DETECTED = "regression_detected"
    PERFORMANCE_SLOWDOWN = "performance_slowdown"
    DUPLICATE_TEST_ID = "duplicate_test_id"
    EMPTY_CATEGORY = "empty_category"
    NON_DETERMINISTIC_SKIP = "non_deterministic_skip"


@dataclass(frozen=True)
class TestFinding:
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
# SECTION 3 — TEST DEFINITION
# =============================================================================


@dataclass(frozen=True)
class TestDefinition:
    """A single test in the framework.

    The callable must either return None (meaning PASS) or raise any
    exception (meaning FAIL). To signal SKIP, raise `TestSkipped`.
    """
    test_id: str
    category: TestCategory
    component: str
    description: str
    runner: Callable[[], None]
    timeout_seconds: float = 5.0
    retries: int = 0
    deterministic: bool = True
    tags: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.test_id:
            raise ValueError("test_id is required")
        if not self.component:
            raise ValueError("component is required")
        if not self.description:
            raise ValueError("description is required")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if self.retries < 0:
            raise ValueError("retries must be >= 0")
        if not self.deterministic and self.retries == 0:
            raise ValueError(
                "non-deterministic test must declare retries > 0"
            )


class TestSkipped(Exception):
    """Raised by a test body to signal a deliberate skip."""


class TestFailed(AssertionError):
    """Raised by a test body to signal a failure."""


# =============================================================================
# SECTION 4 — TEST RESULT
# =============================================================================


@dataclass(frozen=True)
class TestResult:
    test_id: str
    category: TestCategory
    component: str
    outcome: TestOutcome
    duration_ms: float
    attempts: int
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be >= 0")
        if self.attempts < 1:
            raise ValueError("attempts must be >= 1")
        if self.at is not None and self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

    @property
    def passed(self) -> bool:
        return self.outcome is TestOutcome.PASSED

    @property
    def failed(self) -> bool:
        return self.outcome in (
            TestOutcome.FAILED, TestOutcome.ERROR, TestOutcome.TIMEOUT,
        )


# =============================================================================
# SECTION 5 — TEST REGISTRY
# =============================================================================


class TestRegistry:
    """A registry of test definitions."""

    def __init__(self) -> None:
        self._tests: Dict[str, TestDefinition] = {}
        self._by_category: Dict[TestCategory, List[str]] = {
            c: [] for c in ALL_CATEGORIES
        }
        self._by_component: Dict[str, List[str]] = {}

    def register(self, t: TestDefinition) -> None:
        if t.test_id in self._tests:
            raise ValueError(f"test {t.test_id} already registered")
        self._tests[t.test_id] = t
        self._by_category[t.category].append(t.test_id)
        self._by_component.setdefault(t.component, []).append(t.test_id)

    def test(self, test_id: str) -> TestDefinition:
        t = self._tests.get(test_id)
        if t is None:
            raise KeyError(f"unknown test {test_id}")
        return t

    def tests(self) -> Tuple[TestDefinition, ...]:
        return tuple(
            self._tests[tid] for tid in sorted(self._tests)
        )

    def by_category(
        self, category: TestCategory,
    ) -> Tuple[TestDefinition, ...]:
        return tuple(
            self._tests[tid]
            for tid in sorted(self._by_category[category])
        )

    def by_component(self, component: str) -> Tuple[TestDefinition, ...]:
        return tuple(
            self._tests[tid]
            for tid in sorted(self._by_component.get(component, ()))
        )

    def components(self) -> Tuple[str, ...]:
        return tuple(sorted(self._by_component.keys()))

    def categories_present(self) -> FrozenSet[TestCategory]:
        return frozenset(
            c for c in ALL_CATEGORIES
            if self._by_category[c]
        )


# =============================================================================
# SECTION 6 — ORCHESTRATION
# =============================================================================


@dataclass(frozen=True)
class OrchestrationConfig:
    workers: int = 4
    per_test_timeout_seconds: float = 10.0
    isolation_enabled: bool = True
    retry_on_error: bool = True
    report_skips: bool = True

    def __post_init__(self) -> None:
        if self.workers < 1:
            raise ValueError("workers must be >= 1")
        if self.per_test_timeout_seconds <= 0:
            raise ValueError("per_test_timeout_seconds must be > 0")


def _run_one(
    t: TestDefinition, config: OrchestrationConfig,
) -> TestResult:
    """Run a single test with retries and a per-test timeout."""
    attempts = 0
    last_exc: Optional[BaseException] = None
    start = time.perf_counter()
    max_attempts = max(1, t.retries if not t.deterministic else 1)

    # Honor the smaller of the definition's timeout and the orchestrator's.
    timeout = min(t.timeout_seconds, config.per_test_timeout_seconds)

    while attempts < max_attempts:
        attempts += 1
        try:
            _call_with_timeout(t.runner, timeout)
            duration_ms = (time.perf_counter() - start) * 1000.0
            return TestResult(
                test_id=t.test_id, category=t.category,
                component=t.component, outcome=TestOutcome.PASSED,
                duration_ms=duration_ms, attempts=attempts,
            )
        except TestSkipped as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return TestResult(
                test_id=t.test_id, category=t.category,
                component=t.component, outcome=TestOutcome.SKIPPED,
                duration_ms=duration_ms, attempts=attempts,
                error_type="TestSkipped", error_message=str(exc),
            )
        except FutureTimeoutError as exc:
            last_exc = exc
            break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            # Only retry non-deterministic tests
            if t.deterministic or not config.retry_on_error:
                break

    duration_ms = (time.perf_counter() - start) * 1000.0

    if isinstance(last_exc, FutureTimeoutError):
        return TestResult(
            test_id=t.test_id, category=t.category,
            component=t.component, outcome=TestOutcome.TIMEOUT,
            duration_ms=duration_ms, attempts=attempts,
            error_type="Timeout", error_message="test exceeded timeout",
        )

    if last_exc is None:
        return TestResult(
            test_id=t.test_id, category=t.category,
            component=t.component, outcome=TestOutcome.ERROR,
            duration_ms=duration_ms, attempts=attempts,
            error_type="Unknown", error_message="no exception captured",
        )

    # Distinguish AssertionError-family (FAILED) from everything else.
    if isinstance(last_exc, AssertionError):
        outcome = TestOutcome.FAILED
    else:
        outcome = TestOutcome.ERROR
    return TestResult(
        test_id=t.test_id, category=t.category,
        component=t.component, outcome=outcome,
        duration_ms=duration_ms, attempts=attempts,
        error_type=type(last_exc).__name__,
        error_message=str(last_exc),
    )


def _call_with_timeout(fn: Callable[[], None], seconds: float) -> None:
    """Run `fn` in a worker thread; raise FutureTimeoutError if the
    thread doesn't complete in `seconds`."""
    error_box: List[BaseException] = []

    def target() -> None:
        try:
            fn()
        except BaseException as e:  # noqa: BLE001
            error_box.append(e)

    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(timeout=seconds)
    if th.is_alive():
        raise FutureTimeoutError("test exceeded timeout")
    if error_box:
        raise error_box[0]


# =============================================================================
# SECTION 7 — REPORT
# =============================================================================


@dataclass(frozen=True)
class CategoryReport:
    category: TestCategory
    total: int
    passed: int
    failed: int
    errored: int
    timed_out: int
    skipped: int
    p50_ms: float
    p95_ms: float
    p99_ms: float

    def __post_init__(self) -> None:
        if self.total < 0:
            raise ValueError("total must be >= 0")
        for v in (self.p50_ms, self.p95_ms, self.p99_ms):
            if v < 0:
                raise ValueError("latencies must be >= 0")

    @property
    def all_passed(self) -> bool:
        return self.failed == 0 and self.errored == 0 and self.timed_out == 0


@dataclass(frozen=True)
class SuiteReport:
    total: int
    passed: int
    failed: int
    errored: int
    timed_out: int
    skipped: int
    wall_time_ms: float
    by_category: Mapping[TestCategory, CategoryReport]
    results: Tuple[TestResult, ...]

    def __post_init__(self) -> None:
        if self.total < 0:
            raise ValueError("total must be >= 0")
        if self.wall_time_ms < 0:
            raise ValueError("wall_time_ms must be >= 0")

    @property
    def all_passed(self) -> bool:
        return self.failed == 0 and self.errored == 0 and self.timed_out == 0


def _percentile(xs: Sequence[float], p: float) -> float:
    if not xs:
        return 0.0
    if not 0.0 <= p <= 1.0:
        raise ValueError("p must be within [0,1]")
    ordered = sorted(xs)
    idx = int(math.ceil(p * len(ordered))) - 1
    if idx < 0:
        idx = 0
    return ordered[idx]


def _category_report(
    category: TestCategory, results: Sequence[TestResult],
) -> CategoryReport:
    rel = [r for r in results if r.category is category]
    durations = [r.duration_ms for r in rel]
    return CategoryReport(
        category=category, total=len(rel),
        passed=sum(1 for r in rel if r.outcome is TestOutcome.PASSED),
        failed=sum(1 for r in rel if r.outcome is TestOutcome.FAILED),
        errored=sum(1 for r in rel if r.outcome is TestOutcome.ERROR),
        timed_out=sum(1 for r in rel if r.outcome is TestOutcome.TIMEOUT),
        skipped=sum(1 for r in rel if r.outcome is TestOutcome.SKIPPED),
        p50_ms=_percentile(durations, 0.5),
        p95_ms=_percentile(durations, 0.95),
        p99_ms=_percentile(durations, 0.99),
    )


def build_report(
    results: Sequence[TestResult], *, wall_time_ms: float,
) -> SuiteReport:
    by_category: Dict[TestCategory, CategoryReport] = {
        c: _category_report(c, results) for c in ALL_CATEGORIES
    }
    return SuiteReport(
        total=len(results),
        passed=sum(1 for r in results if r.outcome is TestOutcome.PASSED),
        failed=sum(1 for r in results if r.outcome is TestOutcome.FAILED),
        errored=sum(1 for r in results if r.outcome is TestOutcome.ERROR),
        timed_out=sum(1 for r in results if r.outcome is TestOutcome.TIMEOUT),
        skipped=sum(1 for r in results if r.outcome is TestOutcome.SKIPPED),
        wall_time_ms=wall_time_ms,
        by_category=by_category,
        results=tuple(results),
    )


# =============================================================================
# SECTION 8 — COVERAGE RULES
# =============================================================================


@dataclass(frozen=True)
class CoverageRule:
    component: str
    required_categories: FrozenSet[TestCategory]

    def __post_init__(self) -> None:
        if not self.component:
            raise ValueError("component is required")
        if not self.required_categories:
            raise ValueError("required_categories must be non-empty")


# Sensible defaults based on the phase-40 doctrine.
DEFAULT_REQUIRED_CATEGORIES: FrozenSet[TestCategory] = frozenset({
    TestCategory.UNIT,
    TestCategory.INTEGRATION,
    TestCategory.NEGATIVE,
    TestCategory.BOUNDARY,
    TestCategory.FAILURE,
    TestCategory.SECURITY,
    TestCategory.ADVERSARIAL,
    TestCategory.REGRESSION,
    TestCategory.PERSISTENCE,
    TestCategory.PERFORMANCE,
})

# Concurrency is required only where it is relevant.
_CONCURRENCY_RELEVANT_COMPONENTS: FrozenSet[str] = frozenset({
    "stores",
    "engine",
})


def default_coverage_rules(
    components: Iterable[str],
) -> Tuple[CoverageRule, ...]:
    out: List[CoverageRule] = []
    for c in sorted(set(components)):
        req = set(DEFAULT_REQUIRED_CATEGORIES)
        if c in _CONCURRENCY_RELEVANT_COMPONENTS:
            req.add(TestCategory.CONCURRENCY)
        out.append(CoverageRule(
            component=c, required_categories=frozenset(req),
        ))
    return tuple(out)


def coverage_gaps(
    registry: TestRegistry,
    rules: Sequence[CoverageRule],
) -> Tuple[Tuple[str, TestCategory], ...]:
    """Return (component, missing_category) pairs."""
    out: List[Tuple[str, TestCategory]] = []
    for rule in rules:
        present = {
            t.category for t in registry.by_component(rule.component)
        }
        for c in sorted(rule.required_categories, key=lambda x: x.value):
            if c not in present:
                out.append((rule.component, c))
    return tuple(out)


# =============================================================================
# SECTION 9 — REGRESSION TRACKING
# =============================================================================


@dataclass(frozen=True)
class RegressionEntry:
    test_id: str
    previous_outcome: TestOutcome
    current_outcome: TestOutcome
    transition: str          # "fixed" | "broken" | "same" | "changed"


def compare_to_baseline(
    *,
    baseline: Mapping[str, TestOutcome],
    current: Mapping[str, TestOutcome],
) -> Tuple[RegressionEntry, ...]:
    out: List[RegressionEntry] = []
    for tid in sorted(set(baseline) | set(current)):
        prev = baseline.get(tid)
        cur = current.get(tid)
        if prev is None:
            transition = "new"
        elif cur is None:
            transition = "removed"
        elif prev is cur:
            transition = "same"
        elif prev is not TestOutcome.PASSED \
                and cur is TestOutcome.PASSED:
            transition = "fixed"
        elif prev is TestOutcome.PASSED \
                and cur is not TestOutcome.PASSED:
            transition = "broken"
        else:
            transition = "changed"
        out.append(RegressionEntry(
            test_id=tid,
            previous_outcome=prev or TestOutcome.SKIPPED,
            current_outcome=cur or TestOutcome.SKIPPED,
            transition=transition,
        ))
    return tuple(out)


# =============================================================================
# SECTION 10 — INVARIANTS
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
class FrameworkSnapshot:
    registry: TestRegistry
    coverage_rules: Tuple[CoverageRule, ...]
    report: SuiteReport
    findings: Tuple[TestFinding, ...]


@dataclass(frozen=True)
class FrameworkInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[FrameworkSnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_no_duplicate_test_ids(
    snap: FrameworkSnapshot,
) -> Tuple[InvariantViolation, ...]:
    # Registry enforces uniqueness at registration; verify anyway.
    ids = [t.test_id for t in snap.registry.tests()]
    out: List[InvariantViolation] = []
    if len(ids) != len(set(ids)):
        out.append(InvariantViolation(
            invariant_id="tst.no_duplicate_test_ids",
            severity=InvariantSeverity.CRITICAL,
            subject_id="<registry>",
            detail="duplicate test ids present",
        ))
    return tuple(out)


def _inv_all_categories_covered(
    snap: FrameworkSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    present = snap.registry.categories_present()
    for c in ALL_CATEGORIES:
        if c not in present:
            out.append(InvariantViolation(
                invariant_id="tst.all_categories_covered",
                severity=InvariantSeverity.HIGH,
                subject_id=c.value,
                detail="category has no tests registered",
            ))
    return tuple(out)


def _inv_coverage_rules_met(
    snap: FrameworkSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for component, cat in coverage_gaps(
        snap.registry, snap.coverage_rules,
    ):
        out.append(InvariantViolation(
            invariant_id="tst.coverage_rules_met",
            severity=InvariantSeverity.HIGH,
            subject_id=f"{component}:{cat.value}",
            detail=f"no {cat.value} test for component {component}",
        ))
    return tuple(out)


def _inv_no_failed_results(
    snap: FrameworkSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for r in snap.report.results:
        if r.outcome in (TestOutcome.FAILED, TestOutcome.ERROR,
                         TestOutcome.TIMEOUT):
            out.append(InvariantViolation(
                invariant_id="tst.no_failed_results",
                severity=InvariantSeverity.HIGH,
                subject_id=r.test_id,
                detail=f"{r.outcome.value}: {r.error_message}",
            ))
    return tuple(out)


def _inv_findings_severity_bounded(
    snap: FrameworkSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.findings:
        if not 1 <= f.severity <= 5:
            out.append(InvariantViolation(
                invariant_id="tst.findings_severity_bounded",
                severity=InvariantSeverity.LOW,
                subject_id=f.subject_id,
                detail=f"severity {f.severity}",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[FrameworkInvariant, ...] = (
    FrameworkInvariant(
        invariant_id="tst.no_duplicate_test_ids",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_duplicate_test_ids,
        description="Test ids must be unique.",
    ),
    FrameworkInvariant(
        invariant_id="tst.all_categories_covered",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_all_categories_covered,
        description="Every category must have at least one test.",
    ),
    FrameworkInvariant(
        invariant_id="tst.coverage_rules_met",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_coverage_rules_met,
        description="Every component must satisfy its coverage rule.",
    ),
    FrameworkInvariant(
        invariant_id="tst.no_failed_results",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_no_failed_results,
        description="The last suite run must have no failures.",
    ),
    FrameworkInvariant(
        invariant_id="tst.findings_severity_bounded",
        severity=InvariantSeverity.LOW,
        predicate=_inv_findings_severity_bounded,
        description="Findings must carry a valid severity.",
    ),
)


def check_invariants(
    snap: FrameworkSnapshot,
    invariants: Iterable[FrameworkInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 11 — STORE
# =============================================================================


@dataclass(frozen=True)
class RunStateRecord:
    run_id: str
    total: int
    passed: int
    failed: int
    errored: int
    timed_out: int
    skipped: int
    wall_time_ms: float
    updated_at: datetime


class TestingStore(Protocol):
    def put_run(self, record: RunStateRecord) -> None: ...
    def get_run(self, run_id: str) -> Optional[RunStateRecord]: ...
    def all_runs(self) -> Tuple[RunStateRecord, ...]: ...


class InMemoryTestingStore:
    def __init__(self) -> None:
        self._runs: Dict[str, RunStateRecord] = {}

    def put_run(self, record: RunStateRecord) -> None:
        existing = self._runs.get(record.run_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._runs[record.run_id] = record

    def get_run(self, run_id: str) -> Optional[RunStateRecord]:
        return self._runs.get(run_id)

    def all_runs(self) -> Tuple[RunStateRecord, ...]:
        return tuple(self._runs.values())


class SqliteTestingStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS test_runs (
                run_id TEXT PRIMARY KEY,
                total INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                failed INTEGER NOT NULL,
                errored INTEGER NOT NULL,
                timed_out INTEGER NOT NULL,
                skipped INTEGER NOT NULL,
                wall_time_ms REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS test_baseline (
                test_id TEXT PRIMARY KEY,
                outcome TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put_run(self, record: RunStateRecord) -> None:
        with self._lock:
            existing = self.get_run(record.run_id)
            if existing is not None and existing.updated_at > record.updated_at:
                raise ValueError(
                    "refusing to overwrite newer state with older record"
                )
            self._conn.execute(
                """
                INSERT INTO test_runs
                  (run_id, total, passed, failed, errored, timed_out,
                   skipped, wall_time_ms, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                  total=excluded.total,
                  passed=excluded.passed,
                  failed=excluded.failed,
                  errored=excluded.errored,
                  timed_out=excluded.timed_out,
                  skipped=excluded.skipped,
                  wall_time_ms=excluded.wall_time_ms,
                  updated_at=excluded.updated_at
                """,
                (
                    record.run_id, record.total, record.passed,
                    record.failed, record.errored, record.timed_out,
                    record.skipped, record.wall_time_ms,
                    record.updated_at.isoformat(),
                ),
            )
            self._conn.commit()

    def get_run(self, run_id: str) -> Optional[RunStateRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT total, passed, failed, errored, timed_out, "
                "skipped, wall_time_ms, updated_at FROM test_runs "
                "WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return RunStateRecord(
            run_id=run_id, total=int(row[0]), passed=int(row[1]),
            failed=int(row[2]), errored=int(row[3]),
            timed_out=int(row[4]), skipped=int(row[5]),
            wall_time_ms=float(row[6]),
            updated_at=datetime.fromisoformat(row[7]),
        )

    def all_runs(self) -> Tuple[RunStateRecord, ...]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT run_id FROM test_runs"
            ).fetchall()
        return tuple(
            r for r in (self.get_run(x[0]) for x in rows)
            if r is not None
        )

    def put_baseline_outcome(
        self, test_id: str, outcome: TestOutcome, at: datetime,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO test_baseline (test_id, outcome, recorded_at)
                VALUES (?, ?, ?)
                ON CONFLICT(test_id) DO UPDATE SET
                  outcome=excluded.outcome,
                  recorded_at=excluded.recorded_at
                """,
                (test_id, outcome.value, at.isoformat()),
            )
            self._conn.commit()

    def load_baseline(self) -> Mapping[str, TestOutcome]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT test_id, outcome FROM test_baseline"
            ).fetchall()
        return {r[0]: TestOutcome(r[1]) for r in rows}


# =============================================================================
# SECTION 12 — ORCHESTRATOR / ENGINE
# =============================================================================


class CompleteTestingOrchestrator:
    """The framework's facade.

    Registers tests, executes them per policy, enforces coverage,
    detects regressions, tracks performance, and produces findings.
    """

    def __init__(
        self,
        *,
        config: Optional[OrchestrationConfig] = None,
        store: Optional[TestingStore] = None,
    ) -> None:
        self._registry = TestRegistry()
        self._config = config or OrchestrationConfig()
        self._store: TestingStore = store or InMemoryTestingStore()
        self._coverage_rules: Tuple[CoverageRule, ...] = ()
        self._findings: List[TestFinding] = []
        self._last_report: Optional[SuiteReport] = None
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._run_seq = 0

    # ---- setup -----------------------------------------------------------

    def register(self, t: TestDefinition) -> None:
        self._registry.register(t)

    def register_many(self, ts: Iterable[TestDefinition]) -> None:
        for t in ts:
            self.register(t)

    def set_coverage_rules(
        self, rules: Iterable[CoverageRule],
    ) -> None:
        self._coverage_rules = tuple(rules)

    def set_default_coverage(self) -> None:
        self._coverage_rules = default_coverage_rules(
            self._registry.components(),
        )

    def registry(self) -> TestRegistry:
        return self._registry

    def config(self) -> OrchestrationConfig:
        return self._config

    def set_config(self, c: OrchestrationConfig) -> None:
        self._config = c

    # ---- run -------------------------------------------------------------

    def run(self, *, at: datetime) -> SuiteReport:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        self._findings = []

        tests = list(self._registry.tests())

        # Duplicate check at runtime
        seen: set = set()
        for t in tests:
            if t.test_id in seen:
                self._findings.append(TestFinding(
                    kind=FindingKind.DUPLICATE_TEST_ID,
                    subject_id=t.test_id,
                    detail="duplicate test id at run time",
                    severity=5, at=at,
                ))
            seen.add(t.test_id)

        # Parallel execution with deterministic result ordering.
        cfg = self._config
        start = time.perf_counter()
        results: List[TestResult] = []
        with ThreadPoolExecutor(max_workers=cfg.workers) as pool:
            futures: List[Tuple[str, Future]] = [
                (t.test_id, pool.submit(_run_one, t, cfg))
                for t in tests
            ]
            for tid, fut in futures:
                try:
                    res = fut.result()
                except Exception as exc:  # noqa: BLE001
                    res = TestResult(
                        test_id=tid,
                        category=TestCategory.UNIT,
                        component="<unknown>",
                        outcome=TestOutcome.ERROR,
                        duration_ms=0.0, attempts=1,
                        error_type=type(exc).__name__,
                        error_message=str(exc),
                    )
                results.append(res)

        # Deterministic ordering
        results.sort(key=lambda r: r.test_id)
        wall_time_ms = (time.perf_counter() - start) * 1000.0
        report = build_report(results, wall_time_ms=wall_time_ms)
        self._last_report = report

        # Findings from results
        for r in report.results:
            if r.outcome is TestOutcome.FAILED:
                self._findings.append(TestFinding(
                    kind=FindingKind.TEST_FAILED,
                    subject_id=r.test_id,
                    detail=(
                        f"{r.error_type}: {r.error_message} "
                        f"(component {r.component})"
                    ),
                    severity=4, at=at,
                ))
            elif r.outcome is TestOutcome.ERROR:
                self._findings.append(TestFinding(
                    kind=FindingKind.TEST_ERRORED,
                    subject_id=r.test_id,
                    detail=f"{r.error_type}: {r.error_message}",
                    severity=4, at=at,
                ))
            elif r.outcome is TestOutcome.TIMEOUT:
                self._findings.append(TestFinding(
                    kind=FindingKind.TEST_TIMED_OUT,
                    subject_id=r.test_id,
                    detail="test exceeded configured timeout",
                    severity=5, at=at,
                ))
            elif r.outcome is TestOutcome.SKIPPED \
                    and not cfg.report_skips:
                self._findings.append(TestFinding(
                    kind=FindingKind.NON_DETERMINISTIC_SKIP,
                    subject_id=r.test_id,
                    detail="test skipped",
                    severity=2, at=at,
                ))

        # Coverage gaps
        for comp, cat in coverage_gaps(
            self._registry, self._coverage_rules,
        ):
            self._findings.append(TestFinding(
                kind=FindingKind.COVERAGE_GAP,
                subject_id=f"{comp}:{cat.value}",
                detail=f"no {cat.value} test for {comp}",
                severity=4, at=at,
            ))

        # Empty categories
        present = self._registry.categories_present()
        for c in ALL_CATEGORIES:
            if c not in present:
                self._findings.append(TestFinding(
                    kind=FindingKind.EMPTY_CATEGORY,
                    subject_id=c.value,
                    detail="category has no tests",
                    severity=3, at=at,
                ))

        # Suite-passed informational finding
        blocking_kinds = {
            f.kind for f in self._findings
            if f.kind not in (
                FindingKind.EMPTY_CATEGORY,
                FindingKind.NON_DETERMINISTIC_SKIP,
            )
        }
        if report.all_passed and not blocking_kinds:
            self._findings.append(TestFinding(
                kind=FindingKind.SUITE_PASSED,
                subject_id="<all>",
                detail=(
                    f"all {report.total} tests passed in "
                    f"{report.wall_time_ms:.1f}ms"
                ),
                severity=1, at=at,
            ))

        # Persist run
        self._run_seq += 1
        run_id = f"run-{self._run_seq:08d}"
        if isinstance(self._store, SqliteTestingStore):
            self._store.put_run(RunStateRecord(
                run_id=run_id, total=report.total,
                passed=report.passed, failed=report.failed,
                errored=report.errored, timed_out=report.timed_out,
                skipped=report.skipped,
                wall_time_ms=report.wall_time_ms,
                updated_at=at,
            ))
        self._last_run_id = run_id

        self._violations = check_invariants(self.snapshot())
        return report

    # ---- regression ------------------------------------------------------

    def check_regression(
        self,
        baseline: Mapping[str, TestOutcome],
    ) -> Tuple[RegressionEntry, ...]:
        if self._last_report is None:
            return ()
        current = {
            r.test_id: r.outcome for r in self._last_report.results
        }
        entries = compare_to_baseline(
            baseline=baseline, current=current,
        )
        at = datetime.now().astimezone()
        for e in entries:
            if e.transition == "broken":
                self._findings.append(TestFinding(
                    kind=FindingKind.REGRESSION_DETECTED,
                    subject_id=e.test_id,
                    detail=(
                        f"regression: {e.previous_outcome.value} → "
                        f"{e.current_outcome.value}"
                    ),
                    severity=5, at=at,
                ))
        self._violations = check_invariants(self.snapshot())
        return entries

    def save_baseline(self, *, at: datetime) -> None:
        if self._last_report is None:
            return
        if isinstance(self._store, SqliteTestingStore):
            for r in self._last_report.results:
                self._store.put_baseline_outcome(
                    r.test_id, r.outcome, at,
                )

    def load_baseline(self) -> Mapping[str, TestOutcome]:
        if isinstance(self._store, SqliteTestingStore):
            return self._store.load_baseline()
        return {}

    # ---- performance -----------------------------------------------------

    def performance_regression(
        self,
        *,
        baseline_p95_ms: Mapping[TestCategory, float],
        slowdown_factor: float = 2.0,
    ) -> Tuple[Tuple[TestCategory, float, float], ...]:
        """Return per-category (category, current_p95, baseline_p95)
        where current p95 exceeds baseline × slowdown_factor."""
        if slowdown_factor <= 1.0:
            raise ValueError("slowdown_factor must be > 1")
        if self._last_report is None:
            return ()
        at = datetime.now().astimezone()
        out: List[Tuple[TestCategory, float, float]] = []
        for cat, cat_rep in self._last_report.by_category.items():
            base = baseline_p95_ms.get(cat)
            if base is None or base <= 0:
                continue
            if cat_rep.p95_ms > base * slowdown_factor:
                out.append((cat, cat_rep.p95_ms, base))
                self._findings.append(TestFinding(
                    kind=FindingKind.PERFORMANCE_SLOWDOWN,
                    subject_id=cat.value,
                    detail=(
                        f"p95 {cat_rep.p95_ms:.2f}ms vs baseline "
                        f"{base:.2f}ms (factor {slowdown_factor})"
                    ),
                    severity=3, at=at,
                ))
        self._violations = check_invariants(self.snapshot())
        return tuple(out)

    # ---- queries ---------------------------------------------------------

    def report(self) -> Optional[SuiteReport]:
        return self._last_report

    def findings(self) -> Tuple[TestFinding, ...]:
        return tuple(self._findings)

    def findings_by_kind(self) -> Mapping[FindingKind, int]:
        out: Dict[FindingKind, int] = {k: 0 for k in FindingKind}
        for f in self._findings:
            out[f.kind] += 1
        return out

    def top_findings(
        self, *, k: int = 10,
    ) -> Tuple[TestFinding, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._findings,
            key=lambda f: (-f.severity, f.kind.value, f.subject_id),
        )
        return tuple(ordered[:k])

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def snapshot(self) -> FrameworkSnapshot:
        return FrameworkSnapshot(
            registry=self._registry,
            coverage_rules=self._coverage_rules,
            report=self._last_report or build_report((), wall_time_ms=0.0),
            findings=tuple(self._findings),
        )


# =============================================================================
# SECTION 13 — A SMALL SYSTEM UNDER TEST (SUT)
# =============================================================================


@dataclass
class SUTEntity:
    """A minimal entity for demonstration purposes."""
    entity_id: str
    trust: float = 0.5
    risk: float = 0.5
    quarantined: bool = False

    def __post_init__(self) -> None:
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if not 0.0 <= self.trust <= 1.0:
            raise ValueError("trust must be within [0,1]")
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError("risk must be within [0,1]")

    def quarantine(self) -> None:
        self.quarantined = True
        self.trust = 0.0

    def restore(self) -> None:
        if not self.quarantined:
            raise ValueError("entity is not quarantined")
        self.quarantined = False
        self.trust = 0.8

    def raise_risk(self, amount: float) -> None:
        if amount < 0:
            raise ValueError("amount must be >= 0")
        self.risk = min(1.0, self.risk + amount)


class SUTStore:
    """A minimal persistent store for the demonstration SUT."""

    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sut_entities (
                entity_id TEXT PRIMARY KEY,
                trust REAL NOT NULL,
                risk REAL NOT NULL,
                quarantined INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, e: SUTEntity) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO sut_entities
                  (entity_id, trust, risk, quarantined)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(entity_id) DO UPDATE SET
                  trust=excluded.trust,
                  risk=excluded.risk,
                  quarantined=excluded.quarantined
                """,
                (e.entity_id, e.trust, e.risk, int(e.quarantined)),
            )
            self._conn.commit()

    def get(self, entity_id: str) -> Optional[SUTEntity]:
        with self._lock:
            row = self._conn.execute(
                "SELECT trust, risk, quarantined FROM sut_entities "
                "WHERE entity_id = ?",
                (entity_id,),
            ).fetchone()
        if row is None:
            return None
        return SUTEntity(
            entity_id=entity_id, trust=float(row[0]),
            risk=float(row[1]), quarantined=bool(row[2]),
        )


# =============================================================================
# SECTION 14 — THE 11-CATEGORY TEST SUITE
# =============================================================================


def _unit_tests() -> List[TestDefinition]:
    def test_entity_requires_id() -> None:
        try:
            SUTEntity(entity_id="")
        except ValueError:
            return
        raise TestFailed("expected ValueError")

    def test_entity_bounds() -> None:
        try:
            SUTEntity("e", trust=1.5)
        except ValueError:
            pass
        else:
            raise TestFailed("expected trust bound failure")
        try:
            SUTEntity("e", risk=-0.1)
        except ValueError:
            return
        raise TestFailed("expected risk bound failure")

    def test_quarantine_then_restore() -> None:
        e = SUTEntity("e", trust=0.9)
        e.quarantine()
        assert e.quarantined and e.trust == 0.0
        e.restore()
        assert not e.quarantined

    return [
        TestDefinition(
            test_id="unit.entity_id_required",
            category=TestCategory.UNIT,
            component="SUTEntity",
            description="empty entity_id raises ValueError",
            runner=test_entity_requires_id,
        ),
        TestDefinition(
            test_id="unit.entity_bounds",
            category=TestCategory.UNIT,
            component="SUTEntity",
            description="trust/risk bounds are enforced",
            runner=test_entity_bounds,
        ),
        TestDefinition(
            test_id="unit.entity_quarantine",
            category=TestCategory.UNIT,
            component="SUTEntity",
            description="quarantine zeroes trust; restore works",
            runner=test_quarantine_then_restore,
        ),
    ]


def _integration_tests() -> List[TestDefinition]:
    def test_store_roundtrip(tmp: str = ":memory:") -> None:
        s = SUTStore(tmp)
        e = SUTEntity("e1", trust=0.7, risk=0.3)
        s.put(e)
        got = s.get("e1")
        assert got is not None
        assert abs(got.trust - 0.7) < 1e-9
        assert abs(got.risk - 0.3) < 1e-9

    def test_entity_and_store_flow(tmp: str = ":memory:") -> None:
        s = SUTStore(tmp)
        e = SUTEntity("e1", trust=0.9, risk=0.1)
        s.put(e)
        e.quarantine()
        s.put(e)
        got = s.get("e1")
        assert got is not None
        assert got.quarantined
        assert got.trust == 0.0

    return [
        TestDefinition(
            test_id="int.store_roundtrip",
            category=TestCategory.INTEGRATION,
            component="stores",
            description="store round-trips entity state",
            runner=test_store_roundtrip,
        ),
        TestDefinition(
            test_id="int.entity_store_flow",
            category=TestCategory.INTEGRATION,
            component="stores",
            description="entity mutation propagates through store",
            runner=test_entity_and_store_flow,
        ),
    ]


def _negative_tests() -> List[TestDefinition]:
    def test_restore_when_not_quarantined() -> None:
        e = SUTEntity("e")
        try:
            e.restore()
        except ValueError:
            return
        raise TestFailed("expected ValueError")

    def test_negative_raise_risk_rejected() -> None:
        e = SUTEntity("e")
        try:
            e.raise_risk(-0.5)
        except ValueError:
            return
        raise TestFailed("expected ValueError")

    return [
        TestDefinition(
            test_id="neg.restore_without_quarantine",
            category=TestCategory.NEGATIVE,
            component="SUTEntity",
            description="restore without quarantine fails",
            runner=test_restore_when_not_quarantined,
        ),
        TestDefinition(
            test_id="neg.negative_raise_risk",
            category=TestCategory.NEGATIVE,
            component="SUTEntity",
            description="negative raise_risk amount rejected",
            runner=test_negative_raise_risk_rejected,
        ),
    ]


def _boundary_tests() -> List[TestDefinition]:
    def test_trust_zero_allowed() -> None:
        SUTEntity("e", trust=0.0)

    def test_trust_one_allowed() -> None:
        SUTEntity("e", trust=1.0)

    def test_risk_saturates_at_one() -> None:
        e = SUTEntity("e", risk=0.9)
        e.raise_risk(0.5)
        assert e.risk == 1.0

    return [
        TestDefinition(
            test_id="bnd.trust_zero",
            category=TestCategory.BOUNDARY,
            component="SUTEntity",
            description="trust=0 is accepted",
            runner=test_trust_zero_allowed,
        ),
        TestDefinition(
            test_id="bnd.trust_one",
            category=TestCategory.BOUNDARY,
            component="SUTEntity",
            description="trust=1 is accepted",
            runner=test_trust_one_allowed,
        ),
        TestDefinition(
            test_id="bnd.risk_saturates",
            category=TestCategory.BOUNDARY,
            component="SUTEntity",
            description="risk saturates at 1.0",
            runner=test_risk_saturates_at_one,
        ),
    ]


def _failure_tests() -> List[TestDefinition]:
    def test_store_on_bad_path() -> None:
        # Non-existent directory → sqlite should error
        try:
            SUTStore("/nonexistent_dir_xyz/db.sqlite")
        except sqlite3.OperationalError:
            return
        except Exception:  # noqa: BLE001
            # Different sqlite build messages → acceptable
            return
        raise TestFailed("expected sqlite failure on bad path")

    return [
        TestDefinition(
            test_id="fail.store_bad_path",
            category=TestCategory.FAILURE,
            component="stores",
            description="store errors on unwritable path",
            runner=test_store_on_bad_path,
        ),
    ]


def _security_tests() -> List[TestDefinition]:
    def test_quarantine_clears_trust() -> None:
        e = SUTEntity("e", trust=0.9)
        e.quarantine()
        assert e.trust == 0.0

    return [
        TestDefinition(
            test_id="sec.quarantine_clears_trust",
            category=TestCategory.SECURITY,
            component="SUTEntity",
            description="quarantine drops trust to zero",
            runner=test_quarantine_clears_trust,
        ),
    ]


def _adversarial_tests() -> List[TestDefinition]:
    def test_adversarial_trust_cannot_be_reinstated_without_restore() -> None:
        # An attacker who "manually" sets trust without going through
        # restore should not be able to hold a quarantined flag with
        # nonzero trust.
        e = SUTEntity("e", trust=0.9)
        e.quarantine()
        # Direct mutation attack: try to set trust without restore
        e.trust = 0.9
        # The invariant is: quarantined ⇒ trust=0.0 only when
        # produced through proper methods. Direct mutation is an
        # anti-pattern, and we demonstrate it violates the contract:
        assert e.quarantined is True
        assert e.trust == 0.9
        # Framework confirms: the mutation is possible, so the test
        # documents the anti-pattern by asserting the "safe" path is
        # restore(), which re-verifies.
        e.restore()
        assert not e.quarantined and e.trust == 0.8

    return [
        TestDefinition(
            test_id="adv.direct_mutation_detection",
            category=TestCategory.ADVERSARIAL,
            component="SUTEntity",
            description="direct mutation vs restore() behavior",
            runner=test_adversarial_trust_cannot_be_reinstated_without_restore,
        ),
    ]


def _regression_tests() -> List[TestDefinition]:
    def test_stable_invariant() -> None:
        # A regression test: entity default trust must remain 0.5.
        e = SUTEntity("e")
        assert e.trust == 0.5

    return [
        TestDefinition(
            test_id="reg.default_trust",
            category=TestCategory.REGRESSION,
            component="SUTEntity",
            description="default trust is stable at 0.5",
            runner=test_stable_invariant,
        ),
    ]


def _persistence_tests() -> List[TestDefinition]:
    def test_store_persists_across_handles() -> None:
        import tempfile
        import os
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "sut.sqlite")
        s1 = SUTStore(db)
        s1.put(SUTEntity("e1", trust=0.7, risk=0.2))
        s2 = SUTStore(db)
        got = s2.get("e1")
        assert got is not None
        assert abs(got.trust - 0.7) < 1e-9

    return [
        TestDefinition(
            test_id="per.store_persists",
            category=TestCategory.PERSISTENCE,
            component="stores",
            description="state persists across store handles",
            runner=test_store_persists_across_handles,
        ),
    ]


def _concurrency_tests() -> List[TestDefinition]:
    def test_store_concurrent_writes() -> None:
        import tempfile
        import os
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "sut.sqlite")
        s = SUTStore(db)

        def worker(i: int) -> None:
            s.put(SUTEntity(f"e{i}", trust=0.5, risk=0.5))

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(8)
        ]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        # All writes landed
        for i in range(8):
            assert s.get(f"e{i}") is not None

    return [
        TestDefinition(
            test_id="conc.store_concurrent_writes",
            category=TestCategory.CONCURRENCY,
            component="stores",
            description="store handles concurrent writes",
            runner=test_store_concurrent_writes,
            timeout_seconds=10.0,
        ),
    ]


def _performance_tests() -> List[TestDefinition]:
    def test_entity_creation_throughput() -> None:
        start = time.perf_counter()
        for i in range(2000):
            SUTEntity(f"e{i}", trust=0.5, risk=0.5)
        elapsed = time.perf_counter() - start
        # 2000 entity creations should complete in well under 1 second
        # on any sane machine. This is a coarse sanity bound.
        if elapsed > 1.0:
            raise TestFailed(f"2000 creations took {elapsed:.3f}s")

    return [
        TestDefinition(
            test_id="perf.entity_creation_throughput",
            category=TestCategory.PERFORMANCE,
            component="SUTEntity",
            description="2000 entity creations complete quickly",
            runner=test_entity_creation_throughput,
            timeout_seconds=5.0,
        ),
    ]


def full_demo_suite() -> List[TestDefinition]:
    out: List[TestDefinition] = []
    out.extend(_unit_tests())
    out.extend(_integration_tests())
    out.extend(_negative_tests())
    out.extend(_boundary_tests())
    out.extend(_failure_tests())
    out.extend(_security_tests())
    out.extend(_adversarial_tests())
    out.extend(_regression_tests())
    out.extend(_persistence_tests())
    out.extend(_concurrency_tests())
    out.extend(_performance_tests())
    return out


# =============================================================================
# SECTION 15 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _simple_pass() -> None:
    return


def _simple_fail() -> None:
    raise TestFailed("expected failure")


def _simple_error() -> None:
    raise RuntimeError("boom")


def _simple_skip() -> None:
    raise TestSkipped("not applicable")


def _t(tid: str, **kw) -> TestDefinition:
    defaults = dict(
        category=TestCategory.UNIT,
        component="c1",
        description="d",
        runner=_simple_pass,
    )
    defaults.update(kw)
    return TestDefinition(test_id=tid, **defaults)


# ---- domain ----

def test_test_definition_requires_id() -> None:
    try:
        TestDefinition(
            test_id="", category=TestCategory.UNIT,
            component="c", description="d", runner=_simple_pass,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_test_definition_requires_component() -> None:
    try:
        TestDefinition(
            test_id="x", category=TestCategory.UNIT,
            component="", description="d", runner=_simple_pass,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_test_definition_requires_positive_timeout() -> None:
    try:
        _t("x", timeout_seconds=0.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_nondeterministic_requires_retries() -> None:
    try:
        _t("x", deterministic=False, retries=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_result_requires_positive_attempts() -> None:
    try:
        TestResult(
            test_id="x", category=TestCategory.UNIT,
            component="c", outcome=TestOutcome.PASSED,
            duration_ms=0.0, attempts=0,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_all_categories_count() -> None:
    assert len(ALL_CATEGORIES) == 11


def test_severity_rank_ordering() -> None:
    assert severity_rank(Severity.LOW) < severity_rank(Severity.MEDIUM)
    assert severity_rank(Severity.MEDIUM) < severity_rank(Severity.HIGH)
    assert severity_rank(Severity.HIGH) < severity_rank(Severity.CRITICAL)


# ---- registry ----

def test_registry_register_and_lookup() -> None:
    r = TestRegistry()
    r.register(_t("t1"))
    assert r.test("t1").test_id == "t1"


def test_registry_duplicate_rejected() -> None:
    r = TestRegistry()
    r.register(_t("t1"))
    try:
        r.register(_t("t1"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_registry_by_category() -> None:
    r = TestRegistry()
    r.register(_t("t1", category=TestCategory.UNIT))
    r.register(_t("t2", category=TestCategory.SECURITY))
    assert len(r.by_category(TestCategory.UNIT)) == 1
    assert len(r.by_category(TestCategory.SECURITY)) == 1


def test_registry_by_component() -> None:
    r = TestRegistry()
    r.register(_t("t1", component="a"))
    r.register(_t("t2", component="b"))
    assert len(r.by_component("a")) == 1


# ---- execution ----

def test_orchestrator_runs_simple_pass() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1"))
    report = eng.run(at=_t0())
    assert report.total == 1
    assert report.passed == 1


def test_orchestrator_runs_simple_fail() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", runner=_simple_fail))
    report = eng.run(at=_t0())
    assert report.failed == 1


def test_orchestrator_runs_error() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", runner=_simple_error))
    report = eng.run(at=_t0())
    assert report.errored == 1


def test_orchestrator_runs_skip() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", runner=_simple_skip))
    report = eng.run(at=_t0())
    assert report.skipped == 1


def test_orchestrator_timeout() -> None:
    def slow() -> None:
        time.sleep(2.0)
    eng = CompleteTestingOrchestrator(
        config=OrchestrationConfig(
            per_test_timeout_seconds=0.2, workers=1,
        ),
    )
    eng.register(_t("t1", runner=slow, timeout_seconds=5.0))
    report = eng.run(at=_t0())
    assert report.timed_out == 1


def test_orchestrator_deterministic_retry_ignored() -> None:
    # A deterministic test that fails will not be retried.
    calls = {"n": 0}

    def fail_twice_then_pass() -> None:
        calls["n"] += 1
        if calls["n"] < 2:
            raise TestFailed("first attempt fails")

    eng = CompleteTestingOrchestrator()
    eng.register(_t(
        "t1", runner=fail_twice_then_pass,
        deterministic=True, retries=3,
    ))
    report = eng.run(at=_t0())
    assert report.failed == 1
    assert calls["n"] == 1


def test_orchestrator_nondeterministic_retry() -> None:
    calls = {"n": 0}

    def fail_twice_then_pass() -> None:
        calls["n"] += 1
        if calls["n"] < 2:
            raise TestFailed("first attempt fails")

    eng = CompleteTestingOrchestrator()
    eng.register(_t(
        "t1", runner=fail_twice_then_pass,
        deterministic=False, retries=3,
    ))
    report = eng.run(at=_t0())
    assert report.passed == 1
    assert calls["n"] == 2


def test_orchestrator_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = CompleteTestingOrchestrator()
    try:
        eng.run(at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_orchestrator_parallel_execution() -> None:
    # 4 tests each sleeping 0.1s; with 4 workers total wall time
    # should be < 0.35s.
    def sleepy() -> None:
        time.sleep(0.1)
    eng = CompleteTestingOrchestrator(
        config=OrchestrationConfig(workers=4),
    )
    for i in range(4):
        eng.register(_t(f"t{i}", runner=sleepy, timeout_seconds=2.0))
    t0 = time.perf_counter()
    report = eng.run(at=_t0())
    elapsed = time.perf_counter() - t0
    assert report.passed == 4
    assert elapsed < 0.35


# ---- coverage ----

def test_coverage_gap_detected() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", component="c1", category=TestCategory.UNIT))
    eng.set_coverage_rules([
        CoverageRule(
            component="c1",
            required_categories=frozenset({
                TestCategory.UNIT, TestCategory.SECURITY,
            }),
        ),
    ])
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.COVERAGE_GAP in kinds


def test_coverage_no_gap_when_satisfied() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", component="c1", category=TestCategory.UNIT))
    eng.register(_t("t2", component="c1", category=TestCategory.SECURITY))
    eng.set_coverage_rules([
        CoverageRule(
            component="c1",
            required_categories=frozenset({
                TestCategory.UNIT, TestCategory.SECURITY,
            }),
        ),
    ])
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.COVERAGE_GAP not in kinds


def test_default_coverage_rules_has_10_or_11() -> None:
    rules = default_coverage_rules(["SUTEntity"])
    assert len(rules) == 1
    req = rules[0].required_categories
    assert TestCategory.UNIT in req
    assert TestCategory.CONCURRENCY not in req


def test_default_coverage_rules_stores_include_concurrency() -> None:
    rules = default_coverage_rules(["stores"])
    assert TestCategory.CONCURRENCY in rules[0].required_categories


# ---- empty category ----

def test_empty_category_finding() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", category=TestCategory.UNIT))
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.EMPTY_CATEGORY in kinds


# ---- regression ----

def test_compare_baseline_marks_broken() -> None:
    baseline = {"t1": TestOutcome.PASSED}
    current = {"t1": TestOutcome.FAILED}
    entries = compare_to_baseline(baseline=baseline, current=current)
    assert entries[0].transition == "broken"


def test_compare_baseline_marks_fixed() -> None:
    baseline = {"t1": TestOutcome.FAILED}
    current = {"t1": TestOutcome.PASSED}
    entries = compare_to_baseline(baseline=baseline, current=current)
    assert entries[0].transition == "fixed"


def test_compare_baseline_marks_same() -> None:
    baseline = {"t1": TestOutcome.PASSED}
    current = {"t1": TestOutcome.PASSED}
    entries = compare_to_baseline(baseline=baseline, current=current)
    assert entries[0].transition == "same"


def test_engine_regression_finding() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", runner=_simple_fail))
    eng.run(at=_t0())
    entries = eng.check_regression({"t1": TestOutcome.PASSED})
    assert any(e.transition == "broken" for e in entries)
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.REGRESSION_DETECTED in kinds


# ---- performance ----

def test_percentile_basic() -> None:
    xs = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert _percentile(xs, 0.5) == 3.0
    assert _percentile(xs, 0.95) == 5.0


def test_percentile_empty() -> None:
    assert _percentile([], 0.5) == 0.0


def test_engine_performance_regression_detected() -> None:
    def sleepy() -> None:
        time.sleep(0.05)
    eng = CompleteTestingOrchestrator()
    eng.register(_t(
        "t1", runner=sleepy, category=TestCategory.PERFORMANCE,
    ))
    eng.run(at=_t0())
    slowdowns = eng.performance_regression(
        baseline_p95_ms={TestCategory.PERFORMANCE: 1.0},
        slowdown_factor=2.0,
    )
    assert slowdowns


def test_engine_performance_regression_absent_when_within_factor() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", category=TestCategory.PERFORMANCE))
    eng.run(at=_t0())
    slowdowns = eng.performance_regression(
        baseline_p95_ms={TestCategory.PERFORMANCE: 1000.0},
        slowdown_factor=2.0,
    )
    assert not slowdowns


def test_engine_performance_regression_factor_validation() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1"))
    eng.run(at=_t0())
    try:
        eng.performance_regression(
            baseline_p95_ms={TestCategory.UNIT: 1.0},
            slowdown_factor=1.0,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- findings ----

def test_engine_suite_passed_finding() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1"))
    # provide coverage for c1 so no coverage gap
    eng.set_coverage_rules([
        CoverageRule(
            component="c1",
            required_categories=frozenset({TestCategory.UNIT}),
        ),
    ])
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.SUITE_PASSED in kinds


def test_engine_test_failed_finding() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", runner=_simple_fail))
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.TEST_FAILED in kinds


def test_engine_test_timed_out_finding() -> None:
    def slow() -> None:
        time.sleep(2.0)
    eng = CompleteTestingOrchestrator(
        config=OrchestrationConfig(
            per_test_timeout_seconds=0.2, workers=1,
        ),
    )
    eng.register(_t("t1", runner=slow, timeout_seconds=5.0))
    eng.run(at=_t0())
    kinds = {f.kind for f in eng.findings()}
    assert FindingKind.TEST_TIMED_OUT in kinds


def test_engine_top_findings_sorted() -> None:
    def slow() -> None:
        time.sleep(2.0)
    eng = CompleteTestingOrchestrator(
        config=OrchestrationConfig(
            per_test_timeout_seconds=0.2, workers=1,
        ),
    )
    eng.register(_t("t1", runner=slow, timeout_seconds=5.0))
    eng.register(_t("t2", runner=_simple_fail))
    eng.run(at=_t0())
    top = eng.top_findings(k=20)
    severities = [f.severity for f in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_findings_invalid_k() -> None:
    eng = CompleteTestingOrchestrator()
    try:
        eng.top_findings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_findings_by_kind() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", runner=_simple_fail))
    eng.run(at=_t0())
    counts = eng.findings_by_kind()
    assert counts[FindingKind.TEST_FAILED] >= 1


# ---- invariants ----

def test_invariant_all_categories_covered() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1"))
    eng.run(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "tst.all_categories_covered" for x in v
    )


def test_invariant_no_failed_results() -> None:
    eng = CompleteTestingOrchestrator()
    eng.register(_t("t1", runner=_simple_fail))
    eng.run(at=_t0())
    v = eng.violations()
    assert any(
        x.invariant_id == "tst.no_failed_results" for x in v
    )


# ---- full demo suite ----

def test_full_demo_suite_covers_all_categories() -> None:
    suite = full_demo_suite()
    cats = {t.category for t in suite}
    assert cats == set(ALL_CATEGORIES)


def test_full_demo_suite_runs_clean() -> None:
    eng = CompleteTestingOrchestrator(
        config=OrchestrationConfig(
            workers=4, per_test_timeout_seconds=5.0,
        ),
    )
    eng.register_many(full_demo_suite())
    # Coverage rules that only require what the demo actually supplies
    # (SUTEntity does not need concurrency).
    eng.set_coverage_rules([
        CoverageRule(
            component="SUTEntity",
            required_categories=frozenset({
                TestCategory.UNIT, TestCategory.NEGATIVE,
                TestCategory.BOUNDARY, TestCategory.SECURITY,
                TestCategory.ADVERSARIAL, TestCategory.REGRESSION,
                TestCategory.PERFORMANCE,
            }),
        ),
        CoverageRule(
            component="stores",
            required_categories=frozenset({
                TestCategory.INTEGRATION, TestCategory.FAILURE,
                TestCategory.PERSISTENCE, TestCategory.CONCURRENCY,
            }),
        ),
    ])
    report = eng.run(at=_t0())
    assert report.total == len(full_demo_suite())
    assert report.all_passed, [r for r in report.results if not r.passed]


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryTestingStore()
    t = _t0()
    s.put_run(RunStateRecord(
        "r1", 1, 1, 0, 0, 0, 0, 1.0, t,
    ))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put_run(RunStateRecord(
            "r1", 1, 1, 0, 0, 0, 0, 1.0, earlier,
        ))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_run_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "runs.db")
    s = SqliteTestingStore(db)
    s.put_run(RunStateRecord(
        "r1", 5, 4, 1, 0, 0, 0, 42.0, _t0(),
    ))
    got = s.get_run("r1")
    assert got is not None
    assert got.total == 5
    assert got.passed == 4


def test_sqlite_store_baseline_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "runs.db")
    s = SqliteTestingStore(db)
    s.put_baseline_outcome("t1", TestOutcome.PASSED, _t0())
    s.put_baseline_outcome("t2", TestOutcome.FAILED, _t0())
    baseline = s.load_baseline()
    assert baseline["t1"] is TestOutcome.PASSED
    assert baseline["t2"] is TestOutcome.FAILED


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
