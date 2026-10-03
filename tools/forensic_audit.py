#!/usr/bin/env python3
"""Read-only AST inventory for AI-Cyber repository reconstruction."""
from __future__ import annotations
import argparse, ast, json
from collections import Counter, defaultdict
from pathlib import Path

def duplicate_names(names: list[str]) -> dict[str, int]:
    counts = Counter(names)
    return dict(sorted((n, c) for n, c in counts.items() if c > 1))

def scan_file(path: Path) -> dict:
    source = path.read_text(encoding="utf-8", errors="replace")
    out = {"path": str(path), "bytes": len(source.encode("utf-8")),
           "lines": source.count("\n") + 1, "classes": [], "functions": [],
           "imports": [], "syntax_error": None}
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        out["syntax_error"] = {"line": exc.lineno, "column": exc.offset, "message": exc.msg}
        return out
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef): out["classes"].append(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)): out["functions"].append(node.name)
        elif isinstance(node, ast.Import): out["imports"].extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom): out["imports"].append(f"{'.' * node.level}{node.module or ''}")
    return out

def build_report(root: Path) -> dict:
    reports = [scan_file(p) for p in sorted(root.rglob("*.py"))]
    index = defaultdict(list)
    for item in reports:
        for n in item["classes"]: index[f"class:{n}"].append(item["path"])
        for n in item["functions"]: index[f"function:{n}"].append(item["path"])
    return {"root": str(root), "python_file_count": len(reports), "files": reports,
            "cross_file_duplicate_symbols": {k: sorted(v) for k,v in index.items() if len(v) > 1}}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = build_report(args.root.resolve())
    if args.json: print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Python files: {report['python_file_count']}")
        for item in report["files"]:
            status = "OK" if not item["syntax_error"] else "ERROR"
            print(f"{item['path']}: {item['lines']} lines, {len(item['classes'])} classes, {len(item['functions'])} functions, syntax={status}")
            if item["classes"] and duplicate_names(item["classes"]): print("  duplicate classes:", duplicate_names(item["classes"]))
            if item["functions"] and duplicate_names(item["functions"]): print("  duplicate functions:", duplicate_names(item["functions"]))
        print("Cross-file duplicate symbols:", len(report["cross_file_duplicate_symbols"]))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
