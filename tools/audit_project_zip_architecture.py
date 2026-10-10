#!/usr/bin/env python3
"""Inspect the actual Python source stored in ai_cyber_project.zip for architecture evidence."""
from __future__ import annotations

import ast
import json
import re
import sys
import zipfile
from pathlib import Path

TARGET = "IT_tech__MERGED_ALL_FIXES_APPLIED.py"
PATTERNS = {
    "barrier_perimeter": re.compile(r"barrier|perimeter|gateway|ingress|egress", re.I),
    "defence_layers": re.compile(r"layer[_ ]?[123]|layered|defen[cs]e_layer|security_layer", re.I),
    "isolation_quarantine": re.compile(r"isolation|isolat|quarantine|containment|blast_radius|network_zone", re.I),
    "regeneration_recovery": re.compile(r"regenerat|self[_ -]?heal|rebuild|recovery_loop|recovery_plan", re.I),
    "cryptography": re.compile(r"cryptograph|encrypt|decrypt|key_rotation|cipher|signature|kms", re.I),
    "orchestration_entrypoints": re.compile(r"orchestrat|pipeline|run_all|execute|dispatch|main", re.I),
}
EXPECTED_MODULAR_PATHS = (
    "src/ai_cyber_os/hydra.py",
    "src/ai_cyber_os/dataset_pipeline.py",
    "src/ai_cyber_os/knowledge.py",
    "src/ai_cyber_os/protected_data.py",
    "src/ai_cyber_os/canonical.py",
    "pyproject.toml",
    "tests/test_knowledge.py",
    "tests/test_dataset_pipeline.py",
)


def main() -> int:
    archive_path = Path(sys.argv[1] if len(sys.argv) > 1 else "ai_cyber_project.zip")
    if not archive_path.is_file():
        print(json.dumps({"status": "ERROR", "error": f"ZIP not found: {archive_path}"}, indent=2))
        return 2

    with zipfile.ZipFile(archive_path) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        candidates = [n for n in names if n.endswith(TARGET)]
        source_member = candidates[0] if candidates else None
        missing_paths = [
            path for path in EXPECTED_MODULAR_PATHS
            if not any(n == path or n.endswith("/" + path) for n in names)
        ]
        if not source_member:
            print(json.dumps({
                "status": "FAIL", "reason": "IT-tech monolith missing from ZIP",
                "member_count": len(names), "missing_expected_modular_paths": missing_paths,
            }, indent=2))
            return 1
        source_bytes = zf.read(source_member)

    try:
        source = source_bytes.decode("utf-8-sig")
        tree = ast.parse(source, filename=source_member)
    except (UnicodeDecodeError, SyntaxError) as exc:
        print(json.dumps({"status": "FAIL", "source_member": source_member,
                          "parse_error": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 1

    definitions = []
    call_counts: dict[str, int] = {}
    names_seen: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            definitions.append({"kind": kind, "name": node.name, "line": node.lineno})
            names_seen.add(node.name.lower())
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                name = fn.id
            elif isinstance(fn, ast.Attribute):
                name = fn.attr
            else:
                continue
            call_counts[name] = call_counts.get(name, 0) + 1

    categories = {}
    for category, pattern in PATTERNS.items():
        defs = [d for d in definitions if pattern.search(d["name"])]
        source_hits = len(pattern.findall(source))
        call_hits = sorted(
            [{"name": name, "calls": count} for name, count in call_counts.items() if pattern.search(name)],
            key=lambda x: (-x["calls"], x["name"]),
        )[:25]
        categories[category] = {
            "source_token_hits": source_hits,
            "matching_definitions_count": len(defs),
            "matching_definitions_sample": defs[:40],
            "matching_calls_sample": call_hits,
        }

    # Report likely named call edges for architecture-relevant definitions.
    relevant_names = {
        d["name"] for d in definitions
        if any(p.search(d["name"]) for p in PATTERNS.values())
    }
    call_edges = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            fn = child.func
            target = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
            if target in relevant_names and target != node.name:
                call_edges.append({"caller": node.name, "callee": target, "line": child.lineno})
    report = {
        "archive": str(archive_path),
        "status": "REVIEW_REQUIRED",
        "source_member": source_member,
        "source_bytes": len(source_bytes),
        "python_ast_parse": "PASS",
        "class_count": sum(1 for d in definitions if d["kind"] == "class"),
        "function_count": sum(1 for d in definitions if d["kind"] == "function"),
        "expected_modular_paths_missing": missing_paths,
        "modular_layout_complete": not missing_paths,
        "architecture_keyword_and_symbol_evidence": categories,
        "architecture_call_edges_sample": call_edges[:160],
        "important_limit": "Identifier matches and static call edges are evidence for manual review, not proof of runtime enforcement or secure behavior.",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
