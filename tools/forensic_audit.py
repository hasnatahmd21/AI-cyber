#!/usr/bin/env python3
"""Repository-wide forensic baseline for AI-Cyber.

This tool is intentionally analysis-only: it never rewrites legacy sources.
It records concrete AST/symbol/import evidence so reconstruction decisions can
be made without guessing.
"""
from __future__ import annotations

import ast
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "FORENSIC_BASELINE.json"

LEGACY = [
    "Assrf next .py",
    "HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py",
    "HYDRA_MASTER_RECONSTRUCTED_v2.py",
    "HYDRA_patched-3.py",
    "IT_tech__MERGED_ALL_FIXES_APPLIED.py",
    "New tech .py",
]


def audit(path: Path) -> dict:
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    result = {
        "path": path.name,
        "bytes": len(raw),
        "lines": len(text.splitlines()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "parse": "ok",
        "classes": [],
        "functions": [],
        "imports": [],
        "phase_markers": [],
        "syntax_error": None,
    }
    try:
        tree = ast.parse(text, filename=str(path), type_comments=True)
    except SyntaxError as exc:
        result["parse"] = "failed"
        result["syntax_error"] = {
            "line": exc.lineno,
            "offset": exc.offset,
            "message": exc.msg,
        }
        return result

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            result["classes"].append({
                "name": node.name,
                "line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
            })
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result["functions"].append({
                "name": node.name,
                "line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
            })
        elif isinstance(node, ast.Import):
            result["imports"].extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            result["imports"].append(
                f"{node.module or ''}:"
                + ",".join(a.name for a in node.names)
            )

    result["phase_markers"] = [
        i + 1 for i, line in enumerate(text.splitlines())
        if "phase" in line.lower()
        and any(ch.isdigit() for ch in line)
    ]
    return result


def duplicate_names(items: list[dict]) -> dict:
    grouped = defaultdict(list)
    for item in items:
        grouped[item["name"]].append(item["line"])
    return {k: v for k, v in sorted(grouped.items()) if len(v) > 1}


def main() -> None:
    audits = [audit(ROOT / name) for name in LEGACY]
    all_classes = []
    all_functions = []
    for item in audits:
        all_classes.extend(
            {"file": item["path"], **x} for x in item["classes"]
        )
        all_functions.extend(
            {"file": item["path"], **x} for x in item["functions"]
        )

    cross_class = defaultdict(list)
    cross_function = defaultdict(list)
    for item in all_classes:
        cross_class[item["name"]].append(item["file"])
    for item in all_functions:
        cross_function[item["name"]].append(item["file"])

    report = {
        "repository": "hasnatahmd21/AI-cyber",
        "scope": LEGACY,
        "source_count": len(audits),
        "parse_failures": [x for x in audits if x["parse"] != "ok"],
        "files": audits,
        "cross_file_class_collisions": {
            k: sorted(set(v)) for k, v in sorted(cross_class.items())
            if len(set(v)) > 1
        },
        "cross_file_function_collisions": {
            k: sorted(set(v)) for k, v in sorted(cross_function.items())
            if len(set(v)) > 1
        },
        "totals": {
            "bytes": sum(x["bytes"] for x in audits),
            "lines": sum(x["lines"] for x in audits),
            "classes": sum(len(x["classes"]) for x in audits),
            "functions": sum(len(x["functions"]) for x in audits),
        },
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps({
        "sources": report["source_count"],
        "parse_failures": len(report["parse_failures"]),
        "total_lines": report["totals"]["lines"],
        "total_classes": report["totals"]["classes"],
        "total_functions": report["totals"]["functions"],
        "cross_file_class_collisions": len(report["cross_file_class_collisions"]),
        "cross_file_function_collisions": len(report["cross_file_function_collisions"]),
        "output": str(OUTPUT),
    }, indent=2))


if __name__ == "__main__":
    main()
