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


def _has_symlink_component(root: str, rel: str) -> bool:
    if os.path.islink(root):
        return True
    current = root
    for part in rel.split("/"):
        current = os.path.join(current, part)
        if os.path.islink(current):
            return True
    return False


def verify_tree(root: str, baseline: dict[str, str]) -> list[str]:
    actual = _actual_files(root)
    expected = set(baseline)
    problems = []
    for rel in sorted(expected - actual):
        problems.append(("symlink:" if _has_symlink_component(root, rel) else "missing:") + rel)
    for rel in sorted(expected & actual):
        if _has_symlink_component(root, rel):
            problems.append("symlink:" + rel)
        elif _digest(os.path.join(root, *rel.split("/"))) != baseline[rel]:
            problems.append("modified:" + rel)
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
            try:
                os.remove(destination)
                restored.append(problem)
            except OSError:
                return GateResult(False, "cannot remove added file: " + rel)
        else:
            # Never follow a symlink while restoring a baseline-listed path.
            if _has_symlink_component(target, rel) or _has_symlink_component(clean_source, rel):
                return GateResult(False, "refusing symlinked restore path: " + rel)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            try:
                shutil.copyfile(source, destination)
                restored.append(problem)
            except OSError:
                return GateResult(False, "cannot restore file: " + rel)
    remaining = verify_tree(target, baseline)
    return GateResult(not remaining, "restored" if not remaining else "post-restore verification failed", restored)


def write_file_baseline(target_file: str, baseline_path: str, integrity: Integrity) -> None:
    """Sign one trusted source asset outside the Python package (e.g. IT-Tech monolith)."""
    document = {"name": os.path.basename(target_file), "sha256": _digest(target_file)}
    signed = {"document": document, "signature": integrity.sign(json.dumps(document, sort_keys=True).encode())}
    os.makedirs(os.path.dirname(os.path.abspath(baseline_path)), exist_ok=True)
    temp = baseline_path + ".tmp"
    with open(temp, "w", encoding="utf-8") as stream:
        json.dump(signed, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, baseline_path)


def check_file(target_file: str, baseline_path: str, integrity: Integrity,
               clean_source: Optional[str] = None) -> GateResult:
    """Verify a separately signed source file; restore only from a matching clean Git copy."""
    try:
        with open(baseline_path, encoding="utf-8") as stream:
            signed = json.load(stream)
        document, signature = signed["document"], signed["signature"]
        if document.get("name") != os.path.basename(target_file):
            return GateResult(False, "IT-Tech baseline identity mismatch")
        if not integrity.verify(json.dumps(document, sort_keys=True).encode(), signature):
            return GateResult(False, "IT-Tech baseline signature invalid")
        expected = document["sha256"]
    except Exception:
        return GateResult(False, "IT-Tech baseline missing or unreadable")
    try:
        if os.path.islink(target_file):
            return GateResult(False, "refusing symlinked IT-Tech source path")
        if _digest(target_file) == expected:
            return GateResult(True, "clean")
    except OSError:
        pass
    if not clean_source:
        return GateResult(False, "IT-Tech source drift detected")
    try:
        if os.path.islink(clean_source) or _digest(clean_source) != expected:
            return GateResult(False, "trusted Git IT-Tech source does not match signed baseline")
        shutil.copyfile(clean_source, target_file)
        if _digest(target_file) != expected:
            return GateResult(False, "IT-Tech post-restore verification failed")
        return GateResult(True, "restored", [os.path.basename(target_file)])
    except OSError:
        return GateResult(False, "IT-Tech source cannot be verified or restored")
