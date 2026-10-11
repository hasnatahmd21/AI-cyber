"""Signed source baseline, added-file detection, and verified Git-HEAD recovery."""
from __future__ import annotations
import hashlib, json, os, shutil
from dataclasses import dataclass, field
from typing import List, Optional
from .crypto_integrity import Integrity
from .contracts import SecurityError


class IntegrityError(SecurityError): pass


@dataclass
class GateResult:
    ok: bool
    reason: str
    restored: List[str] = field(default_factory=list)


def _digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""): h.update(chunk)
    return h.hexdigest()


def build_baseline(root: str) -> dict[str, str]:
    result = {}
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if d != "__pycache__")
        for name in sorted(files):
            if name.endswith(".pyc"): continue
            path = os.path.join(directory, name)
            result[os.path.relpath(path, root).replace(os.sep, "/")] = _digest(path)
    return result


def _actual_files(root: str) -> set[str]:
    return set(build_baseline(root))


def verify_tree(root: str, baseline: dict[str, str]) -> list[str]:
    actual = _actual_files(root)
    expected = set(baseline)
    problems = []
    for rel in sorted(expected - actual): problems.append("missing:" + rel)
    for rel in sorted(expected & actual):
        if _digest(os.path.join(root, *rel.split("/"))) != baseline[rel]: problems.append("modified:" + rel)
    for rel in sorted(actual - expected): problems.append("added:" + rel)
    return problems


def write_baseline(target: str, baseline_path: str, integrity: Integrity) -> int:
    baseline = build_baseline(target)
    if not baseline: raise IntegrityError("refusing to baseline an empty source tree")
    document = {"baseline": baseline, "signature": integrity.sign(json.dumps(baseline, sort_keys=True).encode())}
    os.makedirs(os.path.dirname(os.path.abspath(baseline_path)), exist_ok=True)
    temp = baseline_path + ".tmp"
    with open(temp, "w", encoding="utf-8") as stream:
        json.dump(document, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, baseline_path)
    return len(baseline)


def check(target: str, baseline_path: str, integrity: Integrity, clean_source: Optional[str] = None) -> GateResult:
    try:
        with open(baseline_path, encoding="utf-8") as stream: document = json.load(stream)
        baseline, signature = document["baseline"], document["signature"]
        if not isinstance(baseline, dict) or not isinstance(signature, str): raise ValueError("invalid schema")
    except Exception:
        return GateResult(False, "baseline missing or unreadable")
    if not integrity.verify(json.dumps(baseline, sort_keys=True).encode(), signature):
        return GateResult(False, "baseline signature invalid")
    problems = verify_tree(target, baseline)
    if not problems: return GateResult(True, "clean")
    if not clean_source: return GateResult(False, f"source drift detected ({len(problems)} problems)")
    if verify_tree(clean_source, baseline):
        return GateResult(False, "trusted Git source does not match signed baseline")
    restored = []
    for problem in problems:
        kind, rel = problem.split(":", 1)
        destination = os.path.normpath(os.path.join(target, *rel.split("/")))
        if not destination.startswith(os.path.normpath(target) + os.sep):
            return GateResult(False, "unsafe path in baseline")
        source = os.path.join(clean_source, *rel.split("/"))
        if kind == "added":
            try: os.remove(destination); restored.append(problem)
            except OSError: return GateResult(False, "cannot remove added file: " + rel)
        else:
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            try: shutil.copyfile(source, destination); restored.append(problem)
            except OSError: return GateResult(False, "cannot restore file: " + rel)
    remaining = verify_tree(target, baseline)
    return GateResult(not remaining, "restored" if not remaining else "post-restore verification failed", restored)
