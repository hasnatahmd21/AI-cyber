#!/usr/bin/env python3
"""Read-only AST inventory for evidence-driven AI-Cyber reconstruction.

The audit records definition locations, signatures, source fingerprints, imports,
and symbol references. It never rewrites legacy source files.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


def duplicate_names(names: list[str]) -> dict[str, int]:
    counts = Counter(names)
    return dict(sorted((n, c) for n, c in counts.items() if c > 1))


def _signature(node: ast.AST) -> str | None:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ast.unparse(node.args)
    return None


def _fingerprint(source: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(source, node) or ""
    normalized = ast.dump(ast.parse(segment), annotate_fields=True, include_attributes=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _defined_names(node: ast.AST) -> set[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return {t.id for t in targets if isinstance(t, ast.Name)}
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return {a.asname or a.name.split(".")[0] for a in node.names}
    return set()


def _loaded_names(node: ast.AST) -> set[str]:
    return {
        n.id for n in ast.walk(node)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    }


def scan_file(path: Path) -> dict:
    source = path.read_text(encoding="utf-8", errors="replace")
    out = {
        "path": str(path),
        "bytes": len(source.encode("utf-8")),
        "lines": source.count("\n") + 1,
        "classes": [],
        "functions": [],
        "imports": [],
        "definitions": [],
        "references": [],
        "syntax_error": None,
    }
    try:
        tree = ast.parse(source, filename=str(path), type_comments=True)
    except SyntaxError as exc:
        out["syntax_error"] = {
            "line": exc.lineno,
            "column": exc.offset,
            "message": exc.msg,
        }
        return out

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            out["classes"].append(node.name)
            out["definitions"].append({
                "kind": "class",
                "name": node.name,
                "line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
                "bases": [ast.unparse(b) for b in node.bases],
                "fingerprint": _fingerprint(source, node),
            })
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out["functions"].append(node.name)
            out["definitions"].append({
                "kind": "function",
                "name": node.name,
                "line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
                "signature": _signature(node),
                "fingerprint": _fingerprint(source, node),
            })
        elif isinstance(node, ast.Import):
            out["imports"].extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            out["imports"].append(f"{'.' * node.level}{node.module or ''}")

    out["references"] = sorted(_loaded_names(tree))
    return out


def build_report(root: Path) -> dict:
    reports = [scan_file(p) for p in sorted(root.rglob("*.py"))]
    index: dict[str, list[dict]] = defaultdict(list)
    fingerprint_index: dict[str, list[dict]] = defaultdict(list)

    for item in reports:
        for definition in item["definitions"]:
            key = f'{definition["kind"]}:{definition["name"]}'
            location = {"path": item["path"], "line": definition["line"]}
            index[key].append(location)
            fingerprint_index[definition["fingerprint"]].append({
                **location,
                "kind": definition["kind"],
                "name": definition["name"],
            })

    duplicate_symbols = {
        k: sorted(v, key=lambda x: (x["path"], x["line"]))
        for k, v in index.items() if len(v) > 1
    }
    exact_duplicate_bodies = {
        k: sorted(v, key=lambda x: (x["path"], x["line"]))
        for k, v in fingerprint_index.items() if len(v) > 1
    }

    return {
        "root": str(root),
        "python_file_count": len(reports),
        "files": reports,
        "cross_file_duplicate_symbols": duplicate_symbols,
        "exact_duplicate_definition_bodies": exact_duplicate_bodies,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = build_report(args.root.resolve())

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(f"Python files: {report['python_file_count']}")
    for item in report["files"]:
        status = "OK" if not item["syntax_error"] else "ERROR"
        print(
            f'{item["path"]}: {item["lines"]} lines, '
            f'{len(item["classes"])} classes, {len(item["functions"])} functions, '
            f"syntax={status}"
        )
        if item["classes"] and duplicate_names(item["classes"]):
            print("  duplicate classes:", duplicate_names(item["classes"]))
        if item["functions"] and duplicate_names(item["functions"]):
            print("  duplicate functions:", duplicate_names(item["functions"]))
    print("Cross-file duplicate symbols:", len(report["cross_file_duplicate_symbols"]))
    print("Exact duplicate definition bodies:", len(report["exact_duplicate_definition_bodies"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
