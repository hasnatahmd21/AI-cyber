#!/usr/bin/env python3
"""Evidence-driven reconstruction generator for AI-Cyber.

This tool does not invent implementations. It parses the selected legacy source,
builds a symbol dependency graph from the actual AST, condenses dependency cycles,
and emits importable responsibility/phase shards. The original source files are
left untouched until the generated system is verified.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "HYDRA_patched-3.py"
OUT = ROOT / "src" / "ai_cyber_os"
MAX_LINES = 7000

PHASE_RE = re.compile(r"(?im)^\s*#*\s*PHASE\s+(\d{1,2})\b|(?im)^\s*#*\s*Phase\s+(\d{1,2})\b")

def phase_at(source: str, lineno: int, headers: list[tuple[int,int]]) -> int:
    best = 0
    for line, phase in headers:
        if line <= lineno:
            best = phase
        else:
            break
    return best

def is_main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    try:
        return (
            isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "__name__"
            and len(node.test.ops) == 1
            and isinstance(node.test.ops[0], ast.Eq)
            and len(node.test.comparators) == 1
            and isinstance(node.test.comparators[0], ast.Constant)
            and node.test.comparators[0].value == "__main__"
        )
    except Exception:
        return False

def defined_names(node: ast.AST) -> set[str]:
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if n is node:
                out.add(n.name)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            out.add(n.id)
        elif isinstance(n, ast.alias):
            out.add(n.asname or n.name.split(".")[0])
    return out

def loaded_names(node: ast.AST) -> set[str]:
    return {
        n.id for n in ast.walk(node)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    }

def dynamic_node(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Name) and n.id in {"globals", "locals", "eval", "exec"}
        for n in ast.walk(node)
    )

def simple_label(node: ast.AST) -> str:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    names = sorted(defined_names(node))
    return names[0] if names else f"statement_{getattr(node, 'lineno', 0)}"

def tarjan(graph: dict[int,set[int]]) -> list[list[int]]:
    index = 0
    stack: list[int] = []
    on: set[int] = set()
    idx: dict[int,int] = {}
    low: dict[int,int] = {}
    comps: list[list[int]] = []

    def visit(v: int):
        nonlocal index
        idx[v] = low[v] = index
        index += 1
        stack.append(v)
        on.add(v)
        for w in graph.get(v, ()):
            if w not in idx:
                visit(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], idx[w])
        if low[v] == idx[v]:
            comp = []
            while True:
                w = stack.pop()
                on.remove(w)
                comp.append(w)
                if w == v:
                    break
            comps.append(comp)
    for v in graph:
        if v not in idx:
            visit(v)
    return comps

def main() -> None:
    if not SOURCE.exists():
        raise SystemExit(f"canonical source not found: {SOURCE}")

    source = SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(SOURCE), type_comments=True)

    headers: list[tuple[int,int]] = []
    for m in PHASE_RE.finditer(source):
        phase = int(m.group(1) or m.group(2))
        line = source.count("\n", 0, m.start()) + 1
        headers.append((line, phase))
    headers.sort()

    import_nodes: list[ast.AST] = []
    nodes: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_nodes.append(node)
        elif is_main_guard(node):
            continue
        else:
            nodes.append(node)

    # The monolith contains a very large number of repeated imports. Normalize
    # them once and copy only the actual import statements into each shard.
    import_texts = []
    seen_imports = set()
    for node in import_nodes:
        text = ast.get_source_segment(source, node)
        if text and text not in seen_imports:
            seen_imports.add(text)
            import_texts.append(text)
    common_imports = "\n".join(import_texts)

    symbol_owner: dict[str,int] = {}
    for i, node in enumerate(nodes):
        for name in defined_names(node):
            # Top-level duplicate definitions are an architectural defect. Keep
            # the first as canonical for now and record the collision.
            symbol_owner.setdefault(name, i)

    graph: dict[int,set[int]] = {i:set() for i in range(len(nodes))}
    dynamic = set()
    for i, node in enumerate(nodes):
        if dynamic_node(node):
            dynamic.add(i)
        for name in loaded_names(node):
            owner = symbol_owner.get(name)
            if owner is not None and owner != i:
                graph[i].add(owner)

    # Collapse cycles so the generated modules have a DAG of symbol imports.
    comps = tarjan(graph)
    comp_id = {node:i for i, comp in enumerate(comps) for node in comp}
    comp_graph: dict[int,set[int]] = {i:set() for i in range(len(comps))}
    for a, deps in graph.items():
        for b in deps:
            ca, cb = comp_id[a], comp_id[b]
            if ca != cb:
                comp_graph[ca].add(cb)

    # Order components by original source position for stable, reviewable output.
    comps.sort(key=lambda comp: min(getattr(nodes[i], "lineno", 0) for i in comp))
    comp_id = {node:i for i, comp in enumerate(comps) for node in comp}
    comp_graph = {i:set() for i in range(len(comps))}
    for i, node in enumerate(nodes):
        ci = comp_id[i]
        for dep in graph[i]:
            cj = comp_id[dep]
            if ci != cj:
                comp_graph[ci].add(cj)

    # Components with dynamic global lookup are isolated in a compatibility
    # runtime shard. They receive explicit imports of the generated public API.
    dynamic_comps = {comp_id[i] for i in dynamic}

    groups: dict[tuple[str,int], list[int]] = defaultdict(list)
    for ci, comp in enumerate(comps):
        first_line = min(getattr(nodes[i], "lineno", 0) for i in comp)
        phase = phase_at(source, first_line, headers)
        role = "verification" if any(
            re.search(r"(?:Test|SelfTest|test_|_tests?$)", simple_label(nodes[i]), re.I)
            for i in comp
        ) else "runtime"
        if ci in dynamic_comps:
            role = "dynamic"
        groups[(role, phase)].append(ci)

    OUT.mkdir(parents=True, exist_ok=True)
    for p in OUT.glob("*.py"):
        p.unlink()

    manifest = {
        "source": SOURCE.name,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "generated_by": "tools/reconstruct.py",
        "node_count": len(nodes),
        "component_count": len(comps),
        "duplicate_top_level_symbols": [],
        "modules": [],
    }

    collisions = defaultdict(list)
    for i, node in enumerate(nodes):
        for name in defined_names(node):
            collisions[name].append(i)
    manifest["duplicate_top_level_symbols"] = {
        k:[nodes[i].lineno for i in v] for k,v in collisions.items() if len(v) > 1
    }

    module_for_comp: dict[int,str] = {}
    module_text: dict[str,list[str]] = {}
    module_components: dict[str,list[int]] = {}

    for (role, phase), cis in sorted(groups.items(), key=lambda x:(x[0][1],x[0][0])):
        shard = 1
        current: list[int] = []
        current_lines = 0
        for ci in cis:
            comp_lines = sum(
                len(ast.get_source_segment(source, nodes[i]).splitlines())
                for i in comps[ci]
                if ast.get_source_segment(source, nodes[i])
            )
            if current and current_lines + comp_lines > MAX_LINES:
                name = f"phase_{phase:02d}_{role}_{shard:02d}"
                module_components[name] = current
                for x in current: module_for_comp[x] = name
                current, current_lines = [], 0
                shard += 1
            current.append(ci)
            current_lines += comp_lines
        if current:
            name = f"phase_{phase:02d}_{role}_{shard:02d}"
            module_components[name] = current
            for x in current: module_for_comp[x] = name

    public_symbols = sorted(symbol_owner)
    for name, cis in module_components.items():
        dep_modules: dict[str,set[str]] = defaultdict(set)
        bodies: list[tuple[int,str]] = []
        for ci in cis:
            for i in sorted(comps[ci], key=lambda j:getattr(nodes[j],"lineno",0)):
                body = ast.get_source_segment(source, nodes[i])
                if not body:
                    continue
                bodies.append((getattr(nodes[i], "lineno", 0), body))
                for ref in loaded_names(nodes[i]):
                    owner = symbol_owner.get(ref)
                    if owner is None:
                        continue
                    other = module_for_comp[comp_id[owner]]
                    if other != name:
                        dep_modules[other].add(ref)

        parts = [
            '"""Generated AI-Cyber responsibility shard. Source-preserving reconstruction."""',
            "from __future__ import annotations",
            "",
            common_imports,
            "",
        ]
        for other in sorted(dep_modules):
            syms = sorted(dep_modules[other])
            parts.append(f"from .{other} import {', '.join(syms)}")
        parts.append("")
        parts.extend(body for _, body in sorted(bodies))
        text = "\n\n".join(parts).rstrip() + "\n"
        (OUT / f"{name}.py").write_text(text, encoding="utf-8")
        manifest["modules"].append({
            "module": name,
            "components": len(cis),
            "lines": len(text.splitlines()),
            "imports": {k: sorted(v) for k,v in dep_modules.items()},
        })

    # Dynamic compatibility module: explicit public imports make string/global
    # lookups resolve against a known namespace rather than accidental monolith
    # ordering.
    dyn_names = [n for n, owner in symbol_owner.items()
                 if module_for_comp[comp_id[owner]] in module_text or any(
                     ci in dynamic_comps for ci in module_components.get(module_for_comp[comp_id[owner]], [])
                 )]
    # Only create this module when dynamic nodes exist; it is intentionally
    # narrow and does not duplicate implementations.
    dyn_modules = [m for m, cis in module_components.items()
                   if any(ci in dynamic_comps for ci in cis)]
    if dyn_modules:
        imports = []
        for name in public_symbols:
            mod = module_for_comp[comp_id[symbol_owner[name]]]
            imports.append(f"from .{mod} import {name}")
        (OUT / "dynamic_runtime.py").write_text(
            '"""Compatibility namespace for legacy dynamic-global lookups."""\n'
            "from __future__ import annotations\n\n" + "\n".join(sorted(set(imports))) + "\n",
            encoding="utf-8",
        )

    init_lines = [
        '"""AI-Cyber reconstructed public surface."""',
        "from __future__ import annotations",
        "",
    ]
    for name in sorted(m["module"] for m in manifest["modules"]):
        init_lines.append(f"from .{name} import *")
    (OUT / "__init__.py").write_text("\n".join(init_lines) + "\n", encoding="utf-8")
    (OUT / "RECONSTRUCTION_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Package-level compatibility entry point.
    compat = ROOT / "src" / "ai_cyber_os.py"
    compat.write_text(
        '"""Compatibility import surface for the reconstructed AI-Cyber package."""\n'
        "from ai_cyber_os.reconstructed import *\n",
        encoding="utf-8",
    )

    print(json.dumps({
        "source": SOURCE.name,
        "nodes": len(nodes),
        "components": len(comps),
        "modules": len(manifest["modules"]),
        "duplicate_top_level_symbols": len(manifest["duplicate_top_level_symbols"]),
        "dynamic_components": len(dynamic_comps),
    }, indent=2))

if __name__ == "__main__":
    main()
