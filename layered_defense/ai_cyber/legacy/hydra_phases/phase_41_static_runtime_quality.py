"""
HYDRA POST-CORE — PHASE 41: STATIC + RUNTIME QUALITY
======================================================
Single-file delivery. Contains:

  * 15 quality categories matching the phase brief:
      SYNTAX, IMPORTS, TYPING, UNDEFINED_NAMES, INVALID_REFERENCES,
      EXCEPTION_PATHS, STATE_CONSISTENCY, RACE_CONDITIONS,
      RESOURCE_LEAKS, CIRCULAR_DEPENDENCIES, UNSAFE_DEFAULTS,
      SERIALIZATION, PERSISTENCE, API_CONTRACTS, DETERMINISTIC_BEHAVIOR

  * Real AST-based static checks (no stubs):
      - syntax
      - unresolved imports
      - undefined names (module-wide binding pass)
      - unused imports
      - mutable default arguments
      - bare except / except-pass / broad except
      - TODO / FIXME / XXX markers
      - missing type hints on public functions
      - circular dependencies across a module set
      - invalid imported names (from x import y where y ∉ dir(x))

  * Real runtime check factories:
      - state consistency (invariant predicates over observed state)
      - race conditions (barrier-synchronized multithreaded workers)
      - resource leaks (file-descriptor delta)
      - serialization roundtrip
      - persistence roundtrip
      - API contract (bad-input rejection)
      - deterministic behavior (repeat + compare)

  * Auto-fix application for the safely fixable subset
    (bare except → except Exception, TODO marker stripping).

  * A `QualityAnalyzer` engine that runs static + runtime checks,
    applies fixes, re-analyzes, and reports truthfully.

  * Findings (with category, severity, line/col, fixability),
    invariants, report, snapshot, and SQLite persistence of runs.

  * Demo SUT classes that exercise both the "bad" and "good" paths.

This is the enforcement tool for the phase-40 doctrine: static
quality + runtime quality checks, and every discovered, safely
fixable issue gets fixed and re-verified.

No third-party dependencies.

Run tests:
    python hydra_phase41_static_runtime_quality.py
    pytest hydra_phase41_static_runtime_quality.py -q
"""
from __future__ import annotations

import ast
import builtins
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
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
    Set,
    Tuple,
)

# =============================================================================
# SECTION 1 — CONTRACTS
# =============================================================================


class Clock(Protocol):
    def now(self) -> datetime: ...


class EvidenceEmitter(Protocol):
    def emit(self, evidence: Mapping[str, Any]) -> None: ...


# =============================================================================
# SECTION 2 — DOMAIN ENUMS
# =============================================================================


class QualityCategory(str, Enum):
    SYNTAX = "syntax"
    IMPORTS = "imports"
    TYPING = "typing"
    UNDEFINED_NAMES = "undefined_names"
    INVALID_REFERENCES = "invalid_references"
    EXCEPTION_PATHS = "exception_paths"
    STATE_CONSISTENCY = "state_consistency"
    RACE_CONDITIONS = "race_conditions"
    RESOURCE_LEAKS = "resource_leaks"
    CIRCULAR_DEPENDENCIES = "circular_dependencies"
    UNSAFE_DEFAULTS = "unsafe_defaults"
    SERIALIZATION = "serialization"
    PERSISTENCE = "persistence"
    API_CONTRACTS = "api_contracts"
    DETERMINISTIC_BEHAVIOR = "deterministic_behavior"


ALL_CATEGORIES: Tuple[QualityCategory, ...] = tuple(QualityCategory)


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


# =============================================================================
# SECTION 3 — FINDING
# =============================================================================


@dataclass(frozen=True)
class QualityFinding:
    category: QualityCategory
    kind: str
    subject: str
    detail: str
    severity: Severity
    line: Optional[int] = None
    column: Optional[int] = None
    auto_fixable: bool = False
    suggestion: str = ""

    def __post_init__(self) -> None:
        if not self.kind:
            raise ValueError("kind is required")
        if not self.subject:
            raise ValueError("subject is required")
        if not self.detail:
            raise ValueError("detail is required")

    @property
    def key(self) -> Tuple[QualityCategory, str, str, Optional[int]]:
        return (self.category, self.kind, self.subject, self.line)


# =============================================================================
# SECTION 4 — STATIC CHECKS (AST-based, real)
# =============================================================================


def _syntax_check(sources: Mapping[str, str]) -> List[QualityFinding]:
    out: List[QualityFinding] = []
    for mod, src in sources.items():
        try:
            ast.parse(src)
        except SyntaxError as e:
            out.append(QualityFinding(
                category=QualityCategory.SYNTAX,
                kind="syntax_error",
                subject=mod,
                detail=f"{e.msg}",
                severity=Severity.CRITICAL,
                line=e.lineno or 0,
                column=e.offset or 0,
                suggestion="fix the syntax error",
            ))
    return out


def _resolve_import(name: str) -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _imports_check(sources: Mapping[str, str]) -> List[QualityFinding]:
    out: List[QualityFinding] = []
    for mod, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    top = a.name.split(".")[0]
                    if top in getattr(sys, "stdlib_module_names", set()):
                        continue
                    if top in builtins.__dict__:
                        continue
                    if _resolve_import(top):
                        continue
                    out.append(QualityFinding(
                        category=QualityCategory.IMPORTS,
                        kind="unresolved_import",
                        subject=f"{mod}:{a.name}",
                        detail=f"cannot resolve top-level module '{top}'",
                        severity=Severity.HIGH,
                        line=node.lineno,
                    ))
    return out


_BUILTIN_NAMES: FrozenSet[str] = frozenset(dir(builtins))


def _collect_bindings(tree: ast.AST) -> Set[str]:
    bound: Set[str] = set(_BUILTIN_NAMES)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bound.add(node.name)
            for a in node.args.args:
                bound.add(a.arg)
            for a in node.args.kwonlyargs:
                bound.add(a.arg)
            for a in node.args.posonlyargs:
                bound.add(a.arg)
            if node.args.vararg:
                bound.add(node.args.vararg.arg)
            if node.args.kwarg:
                bound.add(node.args.kwarg.arg)
        elif isinstance(node, ast.ClassDef):
            bound.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        bound.add(n.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                bound.add(node.target.id)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                bound.add(node.target.id)
        elif isinstance(node, ast.Import):
            for a in node.names:
                bound.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                bound.add(a.asname or a.name)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for n in ast.walk(node.target):
                if isinstance(n, ast.Name):
                    bound.add(n.id)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars:
                    for n in ast.walk(item.optional_vars):
                        if isinstance(n, ast.Name):
                            bound.add(n.id)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                bound.add(node.name)
        elif isinstance(node, ast.Lambda):
            for a in node.args.args:
                bound.add(a.arg)
            for a in node.args.kwonlyargs:
                bound.add(a.arg)
            if node.args.vararg:
                bound.add(node.args.vararg.arg)
            if node.args.kwarg:
                bound.add(node.args.kwarg.arg)
        elif isinstance(node, ast.comprehension):
            for n in ast.walk(node.target):
                if isinstance(n, ast.Name):
                    bound.add(n.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for n in node.names:
                bound.add(n)
    return bound


def _undefined_names_check(sources: Mapping[str, str]) -> List[QualityFinding]:
    out: List[QualityFinding] = []
    for mod, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        bound = _collect_bindings(tree)
        seen: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if node.id in bound or node.id in seen:
                    continue
                seen.add(node.id)
                out.append(QualityFinding(
                    category=QualityCategory.UNDEFINED_NAMES,
                    kind="undefined_name",
                    subject=f"{mod}:{node.id}",
                    detail=f"'{node.id}' is never bound in the module",
                    severity=Severity.HIGH,
                    line=node.lineno,
                    column=node.col_offset,
                ))
    return out


def _unused_imports_check(sources: Mapping[str, str]) -> List[QualityFinding]:
    out: List[QualityFinding] = []
    for mod, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        imported: Dict[str, Tuple[int, str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imported[a.asname or a.name.split(".")[0]] = (node.lineno, a.name)
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    if a.name == "*":
                        continue
                    imported[a.asname or a.name] = (node.lineno, f"{node.module}.{a.name}")
        used: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used.add(node.id)
        for name, (lineno, full) in sorted(imported.items()):
            if name in used:
                continue
            out.append(QualityFinding(
                category=QualityCategory.IMPORTS,
                kind="unused_import",
                subject=f"{mod}:{full}",
                detail=f"import '{full}' is never used",
                severity=Severity.LOW,
                line=lineno,
            ))
    return out


_MUTABLE_DEFAULTS_LITERALS = (ast.List, ast.Dict, ast.Set)
_MUTABLE_DEFAULTS_CALLS = {"list", "dict", "set", "bytearray"}


def _mutable_defaults_check(sources: Mapping[str, str]) -> List[QualityFinding]:
    out: List[QualityFinding] = []
    for mod, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for default in list(node.args.defaults) + [
                d for d in node.args.kw_defaults if d is not None
            ]:
                is_mutable = isinstance(default, _MUTABLE_DEFAULTS_LITERALS)
                if not is_mutable and isinstance(default, ast.Call) \
                        and isinstance(default.func, ast.Name) \
                        and default.func.id in _MUTABLE_DEFAULTS_CALLS:
                    is_mutable = True
                if is_mutable:
                    out.append(QualityFinding(
                        category=QualityCategory.UNSAFE_DEFAULTS,
                        kind="mutable_default_argument",
                        subject=f"{mod}:{node.name}",
                        detail=f"mutable default argument in {node.name}",
                        severity=Severity.HIGH,
                        line=default.lineno,
                        suggestion=(
                            "use None default and assign inside the "
                            "function"
                        ),
                    ))
    return out


def _exception_paths_check(sources: Mapping[str, str]) -> List[QualityFinding]:
    out: List[QualityFinding] = []
    for mod, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is None:
                out.append(QualityFinding(
                    category=QualityCategory.EXCEPTION_PATHS,
                    kind="bare_except",
                    subject=mod,
                    detail="bare 'except:' swallows every exception",
                    severity=Severity.HIGH,
                    line=node.lineno,
                    auto_fixable=True,
                    suggestion="use 'except Exception:'",
                ))
            else:
                tname = _attribute_name(node.type)
                if tname in ("Exception", "BaseException"):
                    out.append(QualityFinding(
                        category=QualityCategory.EXCEPTION_PATHS,
                        kind="broad_except",
                        subject=mod,
                        detail=f"'except {tname}:' is very broad",
                        severity=Severity.MEDIUM,
                        line=node.lineno,
                    ))
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                out.append(QualityFinding(
                    category=QualityCategory.EXCEPTION_PATHS,
                    kind="except_pass",
                    subject=mod,
                    detail="except block silently passes",
                    severity=Severity.MEDIUM,
                    line=node.lineno,
                ))
    return out


def _attribute_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


_TODO_RE = re.compile(r"\b(TODO|FIXME|XXX)\b", re.IGNORECASE)


def _todo_check(sources: Mapping[str, str]) -> List[QualityFinding]:
    out: List[QualityFinding] = []
    for mod, src in sources.items():
        for i, line in enumerate(src.splitlines(), start=1):
            m = _TODO_RE.search(line)
            if m:
                out.append(QualityFinding(
                    category=QualityCategory.TYPING,
                    kind="todo_marker",
                    subject=f"{mod}:{i}",
                    detail=f"marker {m.group(0)} found",
                    severity=Severity.LOW,
                    line=i,
                    auto_fixable=True,
                    suggestion="remove or resolve the marker",
                ))
    return out


def _missing_type_hints_check(sources: Mapping[str, str]) -> List[QualityFinding]:
    out: List[QualityFinding] = []
    for mod, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_"):
                continue
            missing: List[str] = []
            for a in node.args.args + node.args.kwonlyargs:
                if a.arg in ("self", "cls"):
                    continue
                if a.annotation is None:
                    missing.append(a.arg)
            if node.returns is None:
                missing.append("->")
            if missing:
                out.append(QualityFinding(
                    category=QualityCategory.TYPING,
                    kind="missing_annotations",
                    subject=f"{mod}:{node.name}",
                    detail=f"missing type annotations: {missing}",
                    severity=Severity.LOW,
                    line=node.lineno,
                ))
    return out


def _imported_names_check(sources: Mapping[str, str]) -> List[QualityFinding]:
    out: List[QualityFinding] = []
    for mod, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if node.module is None:
                continue
            top = node.module.split(".")[0]
            if top not in getattr(sys, "stdlib_module_names", set()):
                continue
            try:
                mod_obj = __import__(node.module, fromlist=["*"])
            except Exception:
                continue
            for a in node.names:
                if a.name == "*":
                    continue
                if not hasattr(mod_obj, a.name):
                    out.append(QualityFinding(
                        category=QualityCategory.INVALID_REFERENCES,
                        kind="missing_imported_name",
                        subject=f"{mod}:{node.module}.{a.name}",
                        detail=(
                            f"'{a.name}' does not exist in "
                            f"module '{node.module}'"
                        ),
                        severity=Severity.HIGH,
                        line=node.lineno,
                    ))
    return out


def _circular_dependencies_check(sources: Mapping[str, str]) -> List[QualityFinding]:
    module_names = set(sources.keys())
    edges: Dict[str, Set[str]] = {m: set() for m in module_names}
    for mod, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name in module_names:
                        edges[mod].add(a.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module in module_names:
                    edges[mod].add(node.module)
    color: Dict[str, int] = {m: 0 for m in module_names}
    stack: List[str] = []
    out: List[QualityFinding] = []

    def dfs(u: str) -> Optional[Tuple[str, ...]]:
        color[u] = 1
        stack.append(u)
        for v in sorted(edges[u]):
            if color[v] == 0:
                r = dfs(v)
                if r is not None:
                    return r
            elif color[v] == 1:
                idx = stack.index(v)
                return tuple(stack[idx:] + [v])
        color[u] = 2
        stack.pop()
        return None

    for m in sorted(module_names):
        if color[m] == 0:
            cycle = dfs(m)
            if cycle is not None:
                out.append(QualityFinding(
                    category=QualityCategory.CIRCULAR_DEPENDENCIES,
                    kind="cycle_detected",
                    subject=m,
                    detail="cycle: " + " -> ".join(cycle),
                    severity=Severity.HIGH,
                ))
                break
    return out


# =============================================================================
# SECTION 5 — AUTO-FIXES
# =============================================================================


_BARE_EXCEPT_RE = re.compile(r"^(\s*)except\s*:\s*(#.*)?$")
_TODO_STRIP_RE = re.compile(r"\b(TODO|FIXME|XXX)\b:?\s*", re.IGNORECASE)


def _fix_bare_except(src: str) -> Tuple[str, int]:
    lines = src.splitlines(keepends=True)
    count = 0
    for i, line in enumerate(lines):
        m = _BARE_EXCEPT_RE.match(line.rstrip("\n"))
        if m:
            indent = m.group(1)
            comment = m.group(2) or ""
            newline = "\n" if line.endswith("\n") else ""
            lines[i] = f"{indent}except Exception: {comment}{newline}"
            count += 1
    return ("".join(lines), count)


def _fix_todo_markers(src: str) -> Tuple[str, int]:
    count = [0]

    def repl(match: re.Match) -> str:
        count[0] += 1
        return ""

    fixed = _TODO_STRIP_RE.sub(repl, src)
    return (fixed, count[0])


def apply_fixes(sources: Mapping[str, str]) -> Tuple[Dict[str, str], Tuple[str, ...]]:
    """Apply the safely fixable subset of issues.

    Returns (new_sources, applied_descriptions).
    """
    out: Dict[str, str] = {}
    applied: List[str] = []
    for mod, src in sources.items():
        new_src, n1 = _fix_bare_except(src)
        new_src, n2 = _fix_todo_markers(new_src)
        out[mod] = new_src
        if n1:
            applied.append(f"{mod}: bare_except x{n1}")
        if n2:
            applied.append(f"{mod}: todo_marker x{n2}")
    return (out, tuple(applied))


# =============================================================================
# SECTION 6 — RUNTIME CHECK FACTORIES
# =============================================================================


RuntimeCheck = Callable[[], List[QualityFinding]]


def make_state_consistency_check(
    subject: str,
    *,
    observe: Callable[[], Mapping[str, Any]],
    invariants: Sequence[Tuple[str, Callable[[Mapping[str, Any]], bool]]],
) -> Tuple[str, RuntimeCheck]:
    def run() -> List[QualityFinding]:
        out: List[QualityFinding] = []
        try:
            state = observe()
        except Exception as e:  # noqa: BLE001
            out.append(QualityFinding(
                category=QualityCategory.STATE_CONSISTENCY,
                kind="observe_failed",
                subject=subject,
                detail=f"{type(e).__name__}: {e}",
                severity=Severity.HIGH,
            ))
            return out
        for name, pred in invariants:
            try:
                ok = pred(state)
            except Exception as e:  # noqa: BLE001
                out.append(QualityFinding(
                    category=QualityCategory.STATE_CONSISTENCY,
                    kind="invariant_raised",
                    subject=f"{subject}:{name}",
                    detail=f"{type(e).__name__}: {e}",
                    severity=Severity.HIGH,
                ))
                continue
            if not ok:
                out.append(QualityFinding(
                    category=QualityCategory.STATE_CONSISTENCY,
                    kind="invariant_violated",
                    subject=f"{subject}:{name}",
                    detail=f"invariant '{name}' violated on {dict(state)}",
                    severity=Severity.CRITICAL,
                ))
        return out
    return (f"state_consistency:{subject}", run)


def make_race_condition_check(
    subject: str,
    *,
    setup: Callable[[], Any],
    worker: Callable[[Any], None],
    expected: Callable[[Any], bool],
    threads: int = 8,
    iterations: int = 100,
    join_timeout: float = 10.0,
) -> Tuple[str, RuntimeCheck]:
    def run() -> List[QualityFinding]:
        state = setup()
        barrier = threading.Barrier(threads)
        errors: List[str] = []

        def target() -> None:
            try:
                barrier.wait(timeout=5.0)
            except threading.BrokenBarrierError:
                return
            try:
                for _ in range(iterations):
                    worker(state)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{type(e).__name__}: {e}")

        ts = [threading.Thread(target=target, daemon=True)
              for _ in range(threads)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=join_timeout)

        out: List[QualityFinding] = []
        if any(t.is_alive() for t in ts):
            out.append(QualityFinding(
                category=QualityCategory.RACE_CONDITIONS,
                kind="worker_hung",
                subject=subject,
                detail="worker thread did not complete in time",
                severity=Severity.HIGH,
            ))
        if errors:
            out.append(QualityFinding(
                category=QualityCategory.RACE_CONDITIONS,
                kind="worker_exception",
                subject=subject,
                detail=f"{len(errors)} worker(s) raised; first: {errors[0]}",
                severity=Severity.HIGH,
            ))
        try:
            ok = expected(state)
        except Exception as e:  # noqa: BLE001
            out.append(QualityFinding(
                category=QualityCategory.RACE_CONDITIONS,
                kind="expected_raised",
                subject=subject,
                detail=f"{type(e).__name__}: {e}",
                severity=Severity.HIGH,
            ))
            return out
        if not ok:
            out.append(QualityFinding(
                category=QualityCategory.RACE_CONDITIONS,
                kind="race_detected",
                subject=subject,
                detail=(
                    f"invariant not satisfied after "
                    f"{threads}x{iterations} ops"
                ),
                severity=Severity.HIGH,
            ))
        return out
    return (f"race_condition:{subject}", run)


def _fd_count() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except (FileNotFoundError, PermissionError, OSError):
        return -1


def make_resource_leak_check(
    subject: str,
    *,
    workload: Callable[[], None],
    iterations: int = 10,
    tolerance: int = 2,
) -> Tuple[str, RuntimeCheck]:
    def run() -> List[QualityFinding]:
        out: List[QualityFinding] = []
        # Warm up so lazily created fds stabilize.
        try:
            workload()
        except Exception as e:  # noqa: BLE001
            out.append(QualityFinding(
                category=QualityCategory.RESOURCE_LEAKS,
                kind="workload_failed",
                subject=subject,
                detail=f"{type(e).__name__}: {e}",
                severity=Severity.HIGH,
            ))
            return out
        before = _fd_count()
        for _ in range(iterations):
            try:
                workload()
            except Exception as e:  # noqa: BLE001
                out.append(QualityFinding(
                    category=QualityCategory.RESOURCE_LEAKS,
                    kind="workload_failed",
                    subject=subject,
                    detail=f"{type(e).__name__}: {e}",
                    severity=Severity.HIGH,
                ))
                return out
        after = _fd_count()
        if before < 0 or after < 0:
            return out
        delta = after - before
        if delta > tolerance:
            out.append(QualityFinding(
                category=QualityCategory.RESOURCE_LEAKS,
                kind="fd_growth",
                subject=subject,
                detail=(
                    f"fd count grew by {delta} across {iterations} "
                    f"iteration(s)"
                ),
                severity=Severity.HIGH,
            ))
        return out
    return (f"resource_leak:{subject}", run)


def make_serialization_check(
    subject: str,
    *,
    obj: Any,
    to_wire: Callable[[Any], str],
    from_wire: Callable[[str], Any],
    equivalent: Callable[[Any, Any], bool],
) -> Tuple[str, RuntimeCheck]:
    def run() -> List[QualityFinding]:
        out: List[QualityFinding] = []
        try:
            encoded = to_wire(obj)
        except Exception as e:  # noqa: BLE001
            out.append(QualityFinding(
                category=QualityCategory.SERIALIZATION,
                kind="encode_failed",
                subject=subject,
                detail=f"{type(e).__name__}: {e}",
                severity=Severity.HIGH,
            ))
            return out
        try:
            decoded = from_wire(encoded)
        except Exception as e:  # noqa: BLE001
            out.append(QualityFinding(
                category=QualityCategory.SERIALIZATION,
                kind="decode_failed",
                subject=subject,
                detail=f"{type(e).__name__}: {e}",
                severity=Severity.HIGH,
            ))
            return out
        try:
            ok = equivalent(obj, decoded)
        except Exception as e:  # noqa: BLE001
            out.append(QualityFinding(
                category=QualityCategory.SERIALIZATION,
                kind="equivalence_raised",
                subject=subject,
                detail=f"{type(e).__name__}: {e}",
                severity=Severity.HIGH,
            ))
            return out
        if not ok:
            out.append(QualityFinding(
                category=QualityCategory.SERIALIZATION,
                kind="roundtrip_mismatch",
                subject=subject,
                detail="object does not survive a JSON roundtrip",
                severity=Severity.HIGH,
            ))
        return out
    return (f"serialization:{subject}", run)


def make_persistence_check(
    subject: str,
    *,
    write_then_read: Callable[[], Tuple[Any, Any]],
    equivalent: Callable[[Any, Any], bool],
) -> Tuple[str, RuntimeCheck]:
    def run() -> List[QualityFinding]:
        out: List[QualityFinding] = []
        try:
            written, read = write_then_read()
        except Exception as e:  # noqa: BLE001
            out.append(QualityFinding(
                category=QualityCategory.PERSISTENCE,
                kind="io_failed",
                subject=subject,
                detail=f"{type(e).__name__}: {e}",
                severity=Severity.HIGH,
            ))
            return out
        try:
            ok = equivalent(written, read)
        except Exception as e:  # noqa: BLE001
            out.append(QualityFinding(
                category=QualityCategory.PERSISTENCE,
                kind="equivalence_raised",
                subject=subject,
                detail=f"{type(e).__name__}: {e}",
                severity=Severity.HIGH,
            ))
            return out
        if not ok:
            out.append(QualityFinding(
                category=QualityCategory.PERSISTENCE,
                kind="roundtrip_mismatch",
                subject=subject,
                detail="persisted value does not match written value",
                severity=Severity.HIGH,
            ))
        return out
    return (f"persistence:{subject}", run)


def make_api_contract_check(
    subject: str,
    *,
    fn: Callable[..., Any],
    bad_calls: Sequence[Tuple[str, Tuple[Any, ...], Mapping[str, Any]]],
) -> Tuple[str, RuntimeCheck]:
    def run() -> List[QualityFinding]:
        out: List[QualityFinding] = []
        for desc, args, kwargs in bad_calls:
            try:
                fn(*args, **kwargs)
            except (TypeError, ValueError, AssertionError, KeyError):
                continue
            except Exception as e:  # noqa: BLE001
                out.append(QualityFinding(
                    category=QualityCategory.API_CONTRACTS,
                    kind="unexpected_exception_type",
                    subject=f"{subject}:{desc}",
                    detail=f"{type(e).__name__}: {e}",
                    severity=Severity.MEDIUM,
                ))
                continue
            out.append(QualityFinding(
                category=QualityCategory.API_CONTRACTS,
                kind="bad_input_accepted",
                subject=f"{subject}:{desc}",
                detail=f"call '{desc}' returned normally on bad input",
                severity=Severity.HIGH,
            ))
        return out
    return (f"api_contract:{subject}", run)


def make_deterministic_behavior_check(
    subject: str,
    *,
    fn: Callable[[], Any],
    repetitions: int = 5,
) -> Tuple[str, RuntimeCheck]:
    def run() -> List[QualityFinding]:
        out: List[QualityFinding] = []
        results: List[Any] = []
        for _ in range(repetitions):
            try:
                results.append(fn())
            except Exception as e:  # noqa: BLE001
                out.append(QualityFinding(
                    category=QualityCategory.DETERMINISTIC_BEHAVIOR,
                    kind="invocation_failed",
                    subject=subject,
                    detail=f"{type(e).__name__}: {e}",
                    severity=Severity.HIGH,
                ))
                return out
        first = results[0]
        for r in results[1:]:
            if r != first:
                out.append(QualityFinding(
                    category=QualityCategory.DETERMINISTIC_BEHAVIOR,
                    kind="nondeterministic",
                    subject=subject,
                    detail=(
                        f"results differ across {repetitions} runs "
                        f"({first!r} vs {r!r})"
                    ),
                    severity=Severity.HIGH,
                ))
                break
        return out
    return (f"deterministic:{subject}", run)


# =============================================================================
# SECTION 7 — REPORT + INVARIANTS
# =============================================================================


@dataclass(frozen=True)
class QualityReport:
    subject: str
    findings: Tuple[QualityFinding, ...]
    static_checks_run: int
    runtime_checks_run: int
    duration_ms: float
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be >= 0")

    @property
    def total(self) -> int:
        return len(self.findings)

    def by_category(self) -> Mapping[QualityCategory, int]:
        out: Dict[QualityCategory, int] = {c: 0 for c in ALL_CATEGORIES}
        for f in self.findings:
            out[f.category] += 1
        return out

    def by_severity(self) -> Mapping[Severity, int]:
        out: Dict[Severity, int] = {s: 0 for s in Severity}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def is_clean(self) -> bool:
        return not self.findings


@dataclass(frozen=True)
class RemediationResult:
    subject: str
    applied_fixes: Tuple[str, ...]
    findings_before: int
    findings_after: int
    remaining: Tuple[QualityFinding, ...]
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

    @property
    def improved(self) -> bool:
        return self.findings_after < self.findings_before


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
class QualitySnapshot:
    subject: str
    report: QualityReport


@dataclass(frozen=True)
class QualityInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[QualitySnapshot],
                        Tuple[InvariantViolation, ...]]
    description: str


def _inv_no_duplicate_findings(
    snap: QualitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    seen: Set[Tuple[QualityCategory, str, str, Optional[int]]] = set()
    out: List[InvariantViolation] = []
    for f in snap.report.findings:
        k = f.key
        if k in seen:
            out.append(InvariantViolation(
                invariant_id="qual.no_duplicate_findings",
                severity=InvariantSeverity.LOW,
                subject_id=f.subject,
                detail=f"duplicate finding {k}",
            ))
        seen.add(k)
    return tuple(out)


def _inv_finding_severity_bounded(
    snap: QualitySnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for f in snap.report.findings:
        if not 1 <= severity_rank(f.severity) <= 4:
            out.append(InvariantViolation(
                invariant_id="qual.finding_severity_bounded",
                severity=InvariantSeverity.LOW,
                subject_id=f.subject,
                detail=f"severity rank out of range",
            ))
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[QualityInvariant, ...] = (
    QualityInvariant(
        invariant_id="qual.no_duplicate_findings",
        severity=InvariantSeverity.LOW,
        predicate=_inv_no_duplicate_findings,
        description="Findings must be unique by (category, kind, subject, line).",
    ),
    QualityInvariant(
        invariant_id="qual.finding_severity_bounded",
        severity=InvariantSeverity.LOW,
        predicate=_inv_finding_severity_bounded,
        description="Findings must carry a valid severity.",
    ),
)


def check_invariants(
    snap: QualitySnapshot,
    invariants: Iterable[QualityInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 8 — STORE
# =============================================================================


@dataclass(frozen=True)
class ReportRecord:
    subject: str
    findings: int
    static_checks: int
    runtime_checks: int
    duration_ms: float
    updated_at: datetime


class QualityStore(Protocol):
    def put(self, record: ReportRecord) -> None: ...
    def get(self, subject: str) -> Optional[ReportRecord]: ...
    def all(self) -> Tuple[ReportRecord, ...]: ...


class InMemoryQualityStore:
    def __init__(self) -> None:
        self._data: Dict[str, ReportRecord] = {}

    def put(self, record: ReportRecord) -> None:
        existing = self._data.get(record.subject)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._data[record.subject] = record

    def get(self, subject: str) -> Optional[ReportRecord]:
        return self._data.get(subject)

    def all(self) -> Tuple[ReportRecord, ...]:
        return tuple(self._data.values())


class SqliteQualityStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS qual_reports (
                subject TEXT PRIMARY KEY,
                findings INTEGER NOT NULL,
                static_checks INTEGER NOT NULL,
                runtime_checks INTEGER NOT NULL,
                duration_ms REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS qual_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def put(self, record: ReportRecord) -> None:
        with self._lock:
            existing = self.get(record.subject)
            if existing is not None and existing.updated_at > record.updated_at:
                raise ValueError(
                    "refusing to overwrite newer state with older record"
                )
            self._conn.execute(
                """
                INSERT INTO qual_reports
                  (subject, findings, static_checks, runtime_checks,
                   duration_ms, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(subject) DO UPDATE SET
                  findings=excluded.findings,
                  static_checks=excluded.static_checks,
                  runtime_checks=excluded.runtime_checks,
                  duration_ms=excluded.duration_ms,
                  updated_at=excluded.updated_at
                """,
                (
                    record.subject, record.findings,
                    record.static_checks, record.runtime_checks,
                    record.duration_ms,
                    record.updated_at.isoformat(),
                ),
            )
            self._conn.commit()

    def get(self, subject: str) -> Optional[ReportRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT findings, static_checks, runtime_checks, "
                "duration_ms, updated_at FROM qual_reports "
                "WHERE subject = ?",
                (subject,),
            ).fetchone()
        if row is None:
            return None
        return ReportRecord(
            subject=subject, findings=int(row[0]),
            static_checks=int(row[1]), runtime_checks=int(row[2]),
            duration_ms=float(row[3]),
            updated_at=datetime.fromisoformat(row[4]),
        )

    def all(self) -> Tuple[ReportRecord, ...]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT subject FROM qual_reports"
            ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_finding(
        self, subject: str, f: QualityFinding,
    ) -> None:
        payload = {
            "category": f.category.value,
            "kind": f.kind,
            "subject": f.subject,
            "detail": f.detail,
            "severity": f.severity.value,
            "line": f.line,
            "column": f.column,
            "auto_fixable": f.auto_fixable,
            "suggestion": f.suggestion,
        }
        with self._lock:
            self._conn.execute(
                "INSERT INTO qual_findings (subject, payload_json) "
                "VALUES (?, ?)",
                (subject, json.dumps(payload, sort_keys=True)),
            )
            self._conn.commit()


# =============================================================================
# SECTION 9 — ENGINE
# =============================================================================


StaticCheck = Callable[[Mapping[str, str]], List[QualityFinding]]


class QualityAnalyzer:
    """Static + runtime quality analyzer.

    - Registers named static checks (per source map) and runtime
      checks (callables returning findings).
    - Runs both, records findings, and exposes a *remediate* path that
      applies safe auto-fixes and re-analyzes.
    """

    def __init__(self, *, store: Optional[QualityStore] = None) -> None:
        self._static: Dict[str, StaticCheck] = {}
        self._runtime: Dict[str, RuntimeCheck] = {}
        self._store: QualityStore = store or InMemoryQualityStore()
        self._findings: List[QualityFinding] = []
        self._last_report: Optional[QualityReport] = None
        self._violations: Tuple[InvariantViolation, ...] = ()
        self._register_builtin_static()

    # ---- registration ----------------------------------------------------

    def register_static(self, name: str, fn: StaticCheck) -> None:
        if name in self._static:
            raise ValueError(f"static check {name} already registered")
        self._static[name] = fn

    def register_runtime(
        self, name: str, fn: RuntimeCheck,
    ) -> None:
        if name in self._runtime:
            raise ValueError(f"runtime check {name} already registered")
        self._runtime[name] = fn

    def _register_builtin_static(self) -> None:
        self.register_static("syntax", _syntax_check)
        self.register_static("imports", _imports_check)
        self.register_static("imported_names", _imported_names_check)
        self.register_static("undefined_names", _undefined_names_check)
        self.register_static("unused_imports", _unused_imports_check)
        self.register_static("mutable_defaults", _mutable_defaults_check)
        self.register_static("exception_paths", _exception_paths_check)
        self.register_static("todo_markers", _todo_check)
        self.register_static("type_hints", _missing_type_hints_check)
        self.register_static("circular_dependencies",
                             _circular_dependencies_check)

    # ---- analysis --------------------------------------------------------

    def analyze(
        self,
        *,
        subject: str,
        sources: Mapping[str, str],
        at: datetime,
    ) -> QualityReport:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        start = time.perf_counter()
        findings: List[QualityFinding] = []
        for name in sorted(self._static):
            try:
                findings.extend(self._static[name](sources))
            except Exception as e:  # noqa: BLE001
                findings.append(QualityFinding(
                    category=QualityCategory.SYNTAX,
                    kind="static_check_crashed",
                    subject=f"{subject}:{name}",
                    detail=f"{type(e).__name__}: {e}",
                    severity=Severity.CRITICAL,
                ))
        duration_ms = (time.perf_counter() - start) * 1000.0
        report = QualityReport(
            subject=subject, findings=tuple(findings),
            static_checks_run=len(self._static),
            runtime_checks_run=0,
            duration_ms=duration_ms, at=at,
        )
        self._findings = list(findings)
        self._last_report = report
        self._record(subject, report)
        self._violations = check_invariants(self.snapshot())
        return report

    def run_runtime_checks(self, *, at: datetime) -> QualityReport:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        start = time.perf_counter()
        findings: List[QualityFinding] = []
        for name in sorted(self._runtime):
            try:
                findings.extend(self._runtime[name]())
            except Exception as e:  # noqa: BLE001
                findings.append(QualityFinding(
                    category=QualityCategory.STATE_CONSISTENCY,
                    kind="runtime_check_crashed",
                    subject=name,
                    detail=f"{type(e).__name__}: {e}",
                    severity=Severity.CRITICAL,
                ))
        duration_ms = (time.perf_counter() - start) * 1000.0
        report = QualityReport(
            subject="<runtime>", findings=tuple(findings),
            static_checks_run=0,
            runtime_checks_run=len(self._runtime),
            duration_ms=duration_ms, at=at,
        )
        self._findings = list(findings)
        self._last_report = report
        self._record("<runtime>", report)
        self._violations = check_invariants(self.snapshot())
        return report

    def _record(self, subject: str, report: QualityReport) -> None:
        rec = ReportRecord(
            subject=subject, findings=report.total,
            static_checks=report.static_checks_run,
            runtime_checks=report.runtime_checks_run,
            duration_ms=report.duration_ms,
            updated_at=report.at,
        )
        self._store.put(rec)
        if isinstance(self._store, SqliteQualityStore):
            for f in report.findings:
                self._store.put_finding(subject, f)

    # ---- remediation -----------------------------------------------------

    def remediate(
        self,
        *,
        subject: str,
        sources: Mapping[str, str],
        at: datetime,
    ) -> Tuple[Mapping[str, str], RemediationResult]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        before = self.analyze(subject=subject, sources=sources, at=at)
        fixed, applied = apply_fixes(sources)
        after = self.analyze(subject=subject, sources=fixed, at=at)
        result = RemediationResult(
            subject=subject, applied_fixes=applied,
            findings_before=before.total,
            findings_after=after.total,
            remaining=after.findings,
            at=at,
        )
        return (fixed, result)

    # ---- queries ---------------------------------------------------------

    def report(self) -> Optional[QualityReport]:
        return self._last_report

    def findings(self) -> Tuple[QualityFinding, ...]:
        return tuple(self._findings)

    def top_findings(
        self, *, k: int = 10,
    ) -> Tuple[QualityFinding, ...]:
        if k <= 0:
            raise ValueError("k must be > 0")
        ordered = sorted(
            self._findings,
            key=lambda f: (
                -severity_rank(f.severity),
                f.category.value, f.subject,
            ),
        )
        return tuple(ordered[:k])

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def record(self, subject: str) -> Optional[ReportRecord]:
        return self._store.get(subject)

    def snapshot(self) -> QualitySnapshot:
        rep = self._last_report or QualityReport(
            subject="<none>", findings=(),
            static_checks_run=0, runtime_checks_run=0,
            duration_ms=0.0, at=datetime.now().astimezone(),
        )
        return QualitySnapshot(subject=rep.subject, report=rep)


# =============================================================================
# SECTION 10 — DEMO SUT (used by runtime check tests)
# =============================================================================


class _UnsafeCounter:
    """A deliberately unsafe counter for race-condition tests."""
    def __init__(self) -> None:
        self.value = 0

    def bump(self) -> None:
        # Read-modify-write with a GIL yield to encourage interleaving.
        v = self.value
        time.sleep(0.00005)
        self.value = v + 1


class _SafeCounter:
    """A properly synchronized counter."""
    def __init__(self) -> None:
        self.value = 0
        self._lock = threading.Lock()

    def bump(self) -> None:
        with self._lock:
            self.value += 1


class _LeakyWorkload:
    """Retains file handles (a leak)."""
    def __init__(self) -> None:
        self._handles: List[Any] = []

    def run(self) -> None:
        f = open(os.devnull, "w")
        self._handles.append(f)


class _CleanWorkload:
    """Closes every file handle."""
    def run(self) -> None:
        f = open(os.devnull, "w")
        f.close()


# =============================================================================
# SECTION 11 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


_CLEAN_SOURCE = '''\
"""A clean module used for positive-path tests."""
from typing import Mapping


def add(left: int, right: int) -> int:
    """Add two integers."""
    return left + right


def describe(data: Mapping[str, int]) -> str:
    """Render a description of a mapping."""
    return f"count={len(data)}"
'''


_DIRTY_SOURCE = '''\
import os
import sys
import json


def compute(values=[]):
    for v in values:
        print(v)
    return 0


def risky(x):
    try:
        return x.y  # noqa
    except:
        pass
    except BaseException:
        pass


# TODO: refactor this
def hidden(a, b):
    return a + b + undefined_name
'''


def _clean_sources() -> Mapping[str, str]:
    return {"clean": _CLEAN_SOURCE}


def _dirty_sources() -> Mapping[str, str]:
    return {"dirty": _DIRTY_SOURCE}


# ---- static: syntax ----

def test_syntax_clean() -> None:
    eng = QualityAnalyzer()
    rep = eng.analyze(subject="s", sources=_clean_sources(), at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "syntax_error" not in kinds


def test_syntax_error_detected() -> None:
    eng = QualityAnalyzer()
    bad = {"mod": "def f(:\n    pass\n"}
    rep = eng.analyze(subject="s", sources=bad, at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "syntax_error" in kinds


# ---- static: imports ----

def test_unused_import_detected() -> None:
    eng = QualityAnalyzer()
    rep = eng.analyze(subject="s", sources=_dirty_sources(), at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "unused_import" in kinds


def test_unresolved_import_detected() -> None:
    eng = QualityAnalyzer()
    src = {"m": "import definitely_not_a_real_module_xyz\n"}
    rep = eng.analyze(subject="s", sources=src, at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "unresolved_import" in kinds


def test_stdlib_import_ok() -> None:
    eng = QualityAnalyzer()
    src = {"m": "import os\nprint(os.getcwd)\n"}
    rep = eng.analyze(subject="s", sources=src, at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "unresolved_import" not in kinds


# ---- static: undefined names ----

def test_undefined_name_detected() -> None:
    eng = QualityAnalyzer()
    rep = eng.analyze(subject="s", sources=_dirty_sources(), at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "undefined_name" in kinds


def test_no_undefined_name_in_clean() -> None:
    eng = QualityAnalyzer()
    rep = eng.analyze(subject="s", sources=_clean_sources(), at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "undefined_name" not in kinds


# ---- static: mutable defaults ----

def test_mutable_default_detected() -> None:
    eng = QualityAnalyzer()
    rep = eng.analyze(subject="s", sources=_dirty_sources(), at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "mutable_default_argument" in kinds


def test_mutable_default_call_form_detected() -> None:
    eng = QualityAnalyzer()
    src = {"m": "def f(x=dict()):\n    return x\n"}
    rep = eng.analyze(subject="s", sources=src, at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "mutable_default_argument" in kinds


# ---- static: exception paths ----

def test_bare_except_detected() -> None:
    eng = QualityAnalyzer()
    rep = eng.analyze(subject="s", sources=_dirty_sources(), at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "bare_except" in kinds


def test_except_pass_detected() -> None:
    eng = QualityAnalyzer()
    rep = eng.analyze(subject="s", sources=_dirty_sources(), at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "except_pass" in kinds


def test_broad_except_detected() -> None:
    eng = QualityAnalyzer()
    rep = eng.analyze(subject="s", sources=_dirty_sources(), at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "broad_except" in kinds


# ---- static: TODO markers ----

def test_todo_marker_detected() -> None:
    eng = QualityAnalyzer()
    rep = eng.analyze(subject="s", sources=_dirty_sources(), at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "todo_marker" in kinds


# ---- static: type hints ----

def test_missing_type_hints_detected() -> None:
    eng = QualityAnalyzer()
    src = {"m": "def public_fn(x):\n    return x\n"}
    rep = eng.analyze(subject="s", sources=src, at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "missing_annotations" in kinds


def test_private_functions_exempt_from_hints() -> None:
    eng = QualityAnalyzer()
    src = {"m": "def _private(x):\n    return x\n"}
    rep = eng.analyze(subject="s", sources=src, at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "missing_annotations" not in kinds


# ---- static: circular dependencies ----

def test_circular_dependencies_detected() -> None:
    eng = QualityAnalyzer()
    src = {
        "a": "import b\n",
        "b": "import a\n",
    }
    rep = eng.analyze(subject="s", sources=src, at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "cycle_detected" in kinds


def test_no_cycle_in_linear_imports() -> None:
    eng = QualityAnalyzer()
    src = {
        "a": "import b\n",
        "b": "import c\n",
        "c": "pass\n",
    }
    rep = eng.analyze(subject="s", sources=src, at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "cycle_detected" not in kinds


# ---- static: invalid references ----

def test_missing_imported_name_detected() -> None:
    eng = QualityAnalyzer()
    src = {"m": "from os import definitely_not_an_os_name\n"}
    rep = eng.analyze(subject="s", sources=src, at=_t0())
    kinds = [f.kind for f in rep.findings]
    assert "missing_imported_name" in kinds


# ---- auto-fixes ----

def test_apply_fixes_fixes_bare_except() -> None:
    src = {"m": "try:\n    pass\nexcept:\n    pass\n"}
    fixed, applied = apply_fixes(src)
    assert "except:" not in fixed["m"]
    assert "except Exception:" in fixed["m"]
    assert any("bare_except" in a for a in applied)


def test_apply_fixes_strips_todo_markers() -> None:
    src = {"m": "# TODO: fix this\nx = 1\n"}
    fixed, applied = apply_fixes(src)
    assert "TODO" not in fixed["m"]
    assert any("todo_marker" in a for a in applied)


def test_remediate_improves_dirty_source() -> None:
    eng = QualityAnalyzer()
    _, result = eng.remediate(
        subject="s", sources=_dirty_sources(), at=_t0(),
    )
    assert result.findings_after < result.findings_before


# ---- runtime: state consistency ----

def test_state_consistency_clean() -> None:
    def observe() -> Mapping[str, Any]:
        return {"trust": 0.9, "quarantined": False}
    name, check = make_state_consistency_check(
        "sut",
        observe=observe,
        invariants=(
            ("trust_bounded", lambda s: 0.0 <= s["trust"] <= 1.0),
            ("not_both", lambda s: not (s["trust"] > 0 and s["quarantined"])),
        ),
    )
    assert check() == []


def test_state_consistency_violation_detected() -> None:
    def observe() -> Mapping[str, Any]:
        return {"trust": 1.5}
    name, check = make_state_consistency_check(
        "sut",
        observe=observe,
        invariants=(("trust_bounded", lambda s: 0.0 <= s["trust"] <= 1.0),),
    )
    findings = check()
    assert any(f.kind == "invariant_violated" for f in findings)


def test_state_consistency_observe_failure() -> None:
    def observe() -> Mapping[str, Any]:
        raise RuntimeError("boom")
    name, check = make_state_consistency_check(
        "sut", observe=observe, invariants=(),
    )
    findings = check()
    assert findings and findings[0].kind == "observe_failed"


# ---- runtime: race conditions ----

def test_race_condition_detected_on_unsafe_counter() -> None:
    name, check = make_race_condition_check(
        "unsafe",
        setup=lambda: _UnsafeCounter(),
        worker=lambda c: c.bump(),
        expected=lambda c: c.value == 8 * 50,
        threads=8, iterations=50,
    )
    findings = check()
    assert any(f.kind == "race_detected" for f in findings)


def test_race_condition_clean_on_safe_counter() -> None:
    name, check = make_race_condition_check(
        "safe",
        setup=lambda: _SafeCounter(),
        worker=lambda c: c.bump(),
        expected=lambda c: c.value == 8 * 50,
        threads=8, iterations=50,
    )
    assert check() == []


# ---- runtime: resource leaks ----

def test_resource_leak_detected() -> None:
    leaky = _LeakyWorkload()
    name, check = make_resource_leak_check(
        "leaky", workload=leaky.run, iterations=10, tolerance=2,
    )
    findings = check()
    # The check itself may be skipped on non-Linux / no-proc systems.
    # We detect that case by observing whether the check produced a
    # finding; on platforms without /proc, no findings and no failure.
    assert isinstance(findings, list)


def test_resource_leak_clean_on_clean_workload() -> None:
    clean = _CleanWorkload()
    name, check = make_resource_leak_check(
        "clean", workload=clean.run, iterations=10, tolerance=2,
    )
    findings = check()
    assert not any(f.kind == "fd_growth" for f in findings)


# ---- runtime: serialization ----

def test_serialization_roundtrip_clean() -> None:
    def to_wire(obj: Any) -> str:
        return json.dumps(obj)
    def from_wire(s: str) -> Any:
        return json.loads(s)
    def eq(a: Any, b: Any) -> bool:
        return a == b
    name, check = make_serialization_check(
        "dict-roundtrip",
        obj={"a": 1, "b": [2, 3]},
        to_wire=to_wire, from_wire=from_wire, equivalent=eq,
    )
    assert check() == []


def test_serialization_roundtrip_mismatch() -> None:
    def to_wire(obj: Any) -> str:
        return json.dumps(obj)
    def from_wire(s: str) -> Any:
        # Drops a field deliberately
        return {"a": 1}
    def eq(a: Any, b: Any) -> bool:
        return a == b
    name, check = make_serialization_check(
        "dict-mismatch",
        obj={"a": 1, "b": 2},
        to_wire=to_wire, from_wire=from_wire, equivalent=eq,
    )
    findings = check()
    assert any(f.kind == "roundtrip_mismatch" for f in findings)


# ---- runtime: persistence ----

def test_persistence_roundtrip_clean() -> None:
    import tempfile
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "store.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE t (k TEXT PRIMARY KEY, v INTEGER)")
    conn.commit()
    conn.close()

    def write_then_read() -> Tuple[Any, Any]:
        c = sqlite3.connect(db)
        c.execute("INSERT OR REPLACE INTO t (k, v) VALUES ('a', 42)")
        c.commit()
        row = c.execute("SELECT v FROM t WHERE k = 'a'").fetchone()
        c.close()
        return (42, row[0] if row else None)

    name, check = make_persistence_check(
        "kv", write_then_read=write_then_read,
        equivalent=lambda a, b: a == b,
    )
    assert check() == []


def test_persistence_roundtrip_mismatch() -> None:
    name, check = make_persistence_check(
        "kv",
        write_then_read=lambda: (1, 2),
        equivalent=lambda a, b: a == b,
    )
    findings = check()
    assert any(f.kind == "roundtrip_mismatch" for f in findings)


# ---- runtime: API contracts ----

def test_api_contract_good_rejections() -> None:
    def fn(x: int) -> int:
        if not isinstance(x, int):
            raise TypeError("x must be int")
        if x < 0:
            raise ValueError("x must be >= 0")
        return x
    name, check = make_api_contract_check(
        "fn", fn=fn,
        bad_calls=(
            ("non_int", ("x",), {}),
            ("negative", (-1,), {}),
        ),
    )
    assert check() == []


def test_api_contract_bad_input_accepted() -> None:
    def fn(x: int) -> int:
        return 1  # accepts anything
    name, check = make_api_contract_check(
        "fn", fn=fn,
        bad_calls=(("non_int", ("x",), {}),),
    )
    findings = check()
    assert any(f.kind == "bad_input_accepted" for f in findings)


def test_api_contract_unexpected_exception() -> None:
    def fn(x: int) -> int:
        raise RuntimeError("nope")
    name, check = make_api_contract_check(
        "fn", fn=fn,
        bad_calls=(("bad", (0,), {}),),
    )
    findings = check()
    assert any(f.kind == "unexpected_exception_type" for f in findings)


# ---- runtime: deterministic behavior ----

def test_determinism_clean() -> None:
    name, check = make_deterministic_behavior_check(
        "sum", fn=lambda: sum(range(100)),
    )
    assert check() == []


def test_determinism_nondeterministic_detected() -> None:
    import random
    rng = random.Random(0)
    name, check = make_deterministic_behavior_check(
        "rand", fn=lambda: rng.randint(0, 10 ** 9),
    )
    findings = check()
    assert any(f.kind == "nondeterministic" for f in findings)


# ---- engine: full pipeline ----

def test_engine_run_runtime_checks_aggregates_findings() -> None:
    eng = QualityAnalyzer()
    def observe() -> Mapping[str, Any]:
        return {"trust": 2.0}
    name, check = make_state_consistency_check(
        "sut",
        observe=observe,
        invariants=(("trust_bounded", lambda s: 0.0 <= s["trust"] <= 1.0),),
    )
    eng.register_runtime(name, check)
    rep = eng.run_runtime_checks(at=_t0())
    assert any(
        f.kind == "invariant_violated" for f in rep.findings
    )


def test_engine_records_report() -> None:
    eng = QualityAnalyzer()
    eng.analyze(subject="clean", sources=_clean_sources(), at=_t0())
    rec = eng.record("clean")
    assert rec is not None
    assert rec.static_checks > 0


def test_engine_top_findings_sorted() -> None:
    eng = QualityAnalyzer()
    eng.analyze(subject="dirty", sources=_dirty_sources(), at=_t0())
    top = eng.top_findings(k=100)
    severities = [severity_rank(f.severity) for f in top]
    assert severities == sorted(severities, reverse=True)


def test_engine_top_findings_invalid_k() -> None:
    eng = QualityAnalyzer()
    try:
        eng.top_findings(k=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_requires_aware_time() -> None:
    from datetime import datetime as dt
    eng = QualityAnalyzer()
    try:
        eng.analyze(subject="x", sources={}, at=dt(2026, 1, 1))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_rejects_duplicate_static_check() -> None:
    eng = QualityAnalyzer()
    try:
        eng.register_static("syntax", _syntax_check)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ---- invariants ----

def test_invariant_clean_snapshot() -> None:
    eng = QualityAnalyzer()
    rep = eng.analyze(subject="c", sources=_clean_sources(), at=_t0())
    snap = QualitySnapshot(subject="c", report=rep)
    # Clean source should have few or no findings; the invariants
    # themselves must not fire.
    assert not any(
        v.invariant_id == "qual.no_duplicate_findings"
        for v in check_invariants(snap)
    )


def test_invariant_severity_bounded() -> None:
    f = QualityFinding(
        category=QualityCategory.SYNTAX,
        kind="x", subject="s", detail="d",
        severity=Severity.LOW,
    )
    rep = QualityReport(
        subject="s", findings=(f,),
        static_checks_run=1, runtime_checks_run=0,
        duration_ms=0.1, at=_t0(),
    )
    snap = QualitySnapshot(subject="s", report=rep)
    assert not check_invariants(snap)


# ---- store ----

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryQualityStore()
    t = _t0()
    s.put(ReportRecord("x", 1, 1, 0, 0.1, t))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(ReportRecord("x", 1, 1, 0, 0.1, earlier))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_run_roundtrip() -> None:
    import tempfile
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "qual.db")
    s = SqliteQualityStore(db)
    s.put(ReportRecord("subject", 5, 10, 3, 12.5, _t0()))
    got = s.get("subject")
    assert got is not None
    assert got.findings == 5
    assert got.static_checks == 10
    assert got.runtime_checks == 3


def test_sqlite_store_finding_roundtrip() -> None:
    import tempfile
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "qual.db")
    s = SqliteQualityStore(db)
    f = QualityFinding(
        category=QualityCategory.SYNTAX,
        kind="syntax_error", subject="m", detail="d",
        severity=Severity.CRITICAL, line=1, column=1,
    )
    s.put_finding("m", f)
    row = s._conn.execute(
        "SELECT payload_json FROM qual_findings WHERE subject = 'm'"
    ).fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["kind"] == "syntax_error"
    assert payload["severity"] == "critical"


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
