#!/usr/bin/env python3
"""Deterministic forensic inventory for AI-Cyber reconstruction.

Read-only: never edits source files. The JSON report is emitted to stdout or
--output. A non-zero exit is reserved for tool errors; repository defects are
reported as data so CI can inspect the full picture.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

SKIP = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules"}

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def top_level_names(tree: ast.Module) -> dict[str, list[int]]:
    out = defaultdict(list)
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[n.name].append(n.lineno)
        elif isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    out[t.id].append(n.lineno)
    return {k: v for k, v in out.items()}

def phase_markers(source: str) -> list[dict]:
    out = []
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        upper = stripped.upper()
        if "PHASE " in upper and ("HYDRA" in upper or upper.startswith("# PHASE") or upper.startswith("PHASE")):
            out.append({"line": i, "text": stripped[:300]})
    return out

def main_guard_lines(tree: ast.Module) -> list[int]:
    lines = []
    for n in tree.body:
        if isinstance(n, ast.If):
            t = n.test
            if (isinstance(t, ast.Compare) and isinstance(t.left, ast.Name)
                and t.left.id == "__name__" and len(t.comparators) == 1
                and isinstance(t.comparators[0], ast.Constant)
                and t.comparators[0].value == "__main__"):
                lines.append(n.lineno)
    return lines

def scan(path: Path) -> dict:
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    result = {
        "path": path.as_posix(),
        "bytes": len(raw),
        "lines": text.count("\n") + (1 if text else 0),
        "sha256": sha256_bytes(raw),
        "syntax_error": None,
        "top_level_definitions": {},
        "duplicate_top_level_definitions": {},
        "imports": [],
        "main_guards": [],
        "phase_markers": phase_markers(text),
    }
    try:
        tree = ast.parse(text, filename=str(path), type_comments=True)
    except SyntaxError as e:
        result["syntax_error"] = {
            "line": e.lineno, "column": e.offset, "message": e.msg,
            "text": (e.text or "").rstrip("\n")[:500],
        }
        return result

    defs = top_level_names(tree)
    result["top_level_definitions"] = defs
    result["duplicate_top_level_definitions"] = {
        k: v for k, v in defs.items() if len(v) > 1
    }
    result["main_guards"] = main_guard_lines(tree)

    imports = []
    for n in tree.body:
        if isinstance(n, ast.Import):
            imports.extend(a.name for a in n.names)
        elif isinstance(n, ast.ImportFrom):
            imports.append("." * n.level + (n.module or ""))
    result["imports"] = sorted(set(imports))
    return result

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--output")
    args = ap.parse_args()
    root = Path(args.root).resolve()

    files = []
    for p in sorted(root.rglob("*.py")):
        if any(part in SKIP for part in p.parts):
            continue
        files.append(scan(p))

    cross = defaultdict(list)
    for f in files:
        for name, lines in f["top_level_definitions"].items():
            for line in lines:
                cross[name].append({"path": f["path"], "line": line})

    report = {
        "schema": "ai-cyber.forensic-inventory.v1",
        "root": str(root),
        "python_file_count": len(files),
        "syntax_error_files": [f["path"] for f in files if f["syntax_error"]],
        "files_with_duplicate_top_level_definitions": [
            f["path"] for f in files if f["duplicate_top_level_definitions"]
        ],
        "cross_file_duplicate_definitions": {
            k: v for k, v in sorted(cross.items()) if len({x["path"] for x in v}) > 1
        },
        "files": files,
    }
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
