#!/usr/bin/env python3
"""Read-only, reproducible Stage 0 forensic audit for AI-CYBER."""
from __future__ import annotations
import argparse, ast, hashlib, json, os, re, subprocess, sys, tomllib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCHEMA = "ai-cyber.stage0-forensic-audit.v1"
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", ".mypy_cache", ".ruff_cache"}
TEXT_EXTS = {".py", ".pyi", ".toml", ".ini", ".cfg", ".yaml", ".yml", ".json", ".jsonl", ".md", ".txt", ".sh", ".bat", ".ps1", ".sql"}
TEST_RE = re.compile(r"(?:^|/)test_[^/]+\.py$|(?:^|/)[^/]+_test\.py$")
PHASE_RE = re.compile(r"\b(?:HYDRA\s+)?PHASE\s*[-:#]?\s*(\d{1,2})\b", re.I)
SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|private[_-]?key)\b"
    r"\s*[:=]\s*(['\"])(?!\s*(?:\$|os\.environ|environ|none|null|your_|<|redacted|example|changeme|test|dummy))"
    r"([^'\"\n]{8,})\1"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def discover_files(root: Path) -> list[Path]:
    """Use Git's tracked file set when available; otherwise walk fixture trees."""
    try:
        proc = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True, text=False, timeout=20)
        names = [x.decode("utf-8", "surrogateescape") for x in proc.stdout.split(b"\0") if x]
        return sorted((root / n for n in names if not any(s in Path(n).parts for s in SKIP_DIRS) and ((root / n).exists() or (root / n).is_symlink())), key=lambda p: p.as_posix())
    except (OSError, subprocess.SubprocessError):
        return sorted((p for p in root.rglob("*") if (p.is_file() or p.is_symlink()) and not any(s in p.relative_to(root).parts for s in SKIP_DIRS)), key=lambda p: p.as_posix())


def git_commit(root: Path) -> str | None:
    try:
        return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [v for child in target.elts for v in target_names(child)]
    return []


def top_level_definitions(tree: ast.Module) -> dict[str, list[int]]:
    out: dict[str, list[int]] = defaultdict(list)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[node.name].append(node.lineno)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                for name in target_names(target):
                    out[name].append(node.lineno)
    return dict(sorted(out.items()))


def scoped_duplicates(tree: ast.Module) -> dict[str, list[int]]:
    names: dict[str, list[int]] = defaultdict(list)
    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.scopes: list[str] = []
        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            names[".".join(self.scopes + [node.name])].append(node.lineno)
            self.scopes.append(node.name)
            for child in node.body:
                self.visit(child)
            self.scopes.pop()
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            names[".".join(self.scopes + [node.name])].append(node.lineno)
            self.scopes.append(node.name)
            for child in node.body:
                self.visit(child)
            self.scopes.pop()
        visit_AsyncFunctionDef = visit_FunctionDef
    Visitor().visit(tree)
    return {k: v for k, v in sorted(names.items()) if len(v) > 1}


def module_name(path: Path, roots: list[Path]) -> str | None:
    for base in roots:
        try:
            parts = list(path.relative_to(base).with_suffix("").parts)
        except ValueError:
            continue
        if parts and parts[-1] == "__init__":
            parts.pop()
        if parts:
            return ".".join(parts)
    return None


def resolve_local(module: str, roots: list[Path]) -> str | None:
    if not module:
        return None
    rel = Path(*module.split("."))
    for base in roots:
        for candidate in (base / rel.with_suffix(".py"), base / rel / "__init__.py", base / rel.with_suffix(".pyi")):
            if candidate.is_file():
                return candidate.as_posix()
    return None


def resolve_import(module: str, path: Path, roots: list[Path], stdlib: set[str]) -> dict[str, str]:
    normalized = module.lstrip(".")
    if module.startswith("."):
        current = module_name(path, roots)
        package = current if path.name == "__init__.py" else (current.rpartition(".")[0] if current else "")
        level = len(module) - len(module.lstrip("."))
        parts = package.split(".") if package else []
        if level > 1:
            parts = parts[:max(0, len(parts) - level + 1)]
        normalized = ".".join([*parts, normalized] if normalized else parts)
    local = resolve_local(normalized, roots)
    if local:
        return {"module": module, "classification": "local", "resolved_path": local}
    top = normalized.split(".", 1)[0] if normalized else ""
    if top in stdlib or top == "__future__":
        return {"module": module, "classification": "stdlib", "resolved_path": ""}
    return {"module": module, "classification": "external_or_unresolved" if normalized else "relative_unresolved", "resolved_path": ""}


def declared_dependencies(root: Path) -> dict[str, Any]:
    deps: set[str] = set()
    manifests: list[str] = []
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        manifests.append("pyproject.toml")
        try:
            obj = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            entries = list(obj.get("project", {}).get("dependencies", []))
            for group in obj.get("project", {}).get("optional-dependencies", {}).values():
                entries.extend(group)
            for item in entries:
                name = re.split(r"[<>=!~;\[]", str(item).strip(), 1)[0].strip().lower().replace("_", "-")
                if name:
                    deps.add(name)
        except (ValueError, OSError) as exc:
            return {"manifest_files": manifests, "declared": [], "parse_error": type(exc).__name__}
    for pattern in ("requirements*.txt", "constraints*.txt"):
        for p in sorted(root.glob(pattern)):
            manifests.append(p.name)
            try:
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    item = line.strip()
                    if item and not item.startswith(("#", "-", ".", "/")):
                        name = re.split(r"[<>=!~;\[]", item, 1)[0].strip().lower().replace("_", "-")
                        if name:
                            deps.add(name)
            except OSError:
                pass
    return {"manifest_files": sorted(set(manifests)), "declared": sorted(deps)}


def security_findings(text: str, path: str) -> list[dict[str, Any]]:
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        rules = []
        if SECRET_RE.search(line):
            rules.append(("possible_hardcoded_secret", "high", "review_required"))
        if PRIVATE_KEY_RE.search(line):
            rules.append(("private_key_material_in_source", "critical", "high"))
        low = line.lower()
        if re.search(r"\bverify\s*=\s*false\b", low) or "CERT_NONE" in line:
            rules.append(("tls_verification_disabled_indicator", "high", "medium"))
        if re.search(r"\b(?:shell\s*=\s*true|os\.system\s*\(|os\.popen\s*\()", line) or re.search(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output).*\bshell\s*=\s*true", low):
            rules.append(("shell_command_execution_indicator", "medium", "medium"))
        if re.search(r"\b(?:eval|exec)\s*\(", line):
            rules.append(("dynamic_code_execution_indicator", "high", "medium"))
        if re.search(r"\bpickle\.(?:load|loads)\s*\(", line):
            rules.append(("pickle_deserialization_indicator", "high", "medium"))
        if re.search(r"\byaml\.load\s*\(", line) and "safe_load" not in line:
            rules.append(("yaml_load_indicator", "medium", "review_required"))
        if re.search(r"\bhashlib\.(?:md5|sha1)\s*\(", line) or re.search(r"\b(?:MD5|SHA1|DES|RC4)\b", line):
            rules.append(("weak_crypto_indicator", "medium", "review_required"))
        if re.search(r"https?://", line) and not re.search(r"https://", line):
            rules.append(("plaintext_http_url_indicator", "low", "review_required"))
        findings.extend({"rule_id": rule, "severity": sev, "path": path, "line": number, "confidence": confidence} for rule, sev, confidence in rules)
    return findings


def scan_file(path: Path, root: Path, roots: list[Path], stdlib: set[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rel = path.relative_to(root).as_posix()
    link = path.is_symlink()
    raw = os.fsencode(os.readlink(path)) if link else path.read_bytes()
    suffix = path.suffix.lower()
    row = {"path": rel, "kind": "symlink" if link else "file", "bytes": len(raw), "sha256": sha256_bytes(raw), "extension": suffix, "line_count": None}
    findings = []
    if suffix == ".py" and not link:
        text = raw.decode("utf-8", "replace")
        row.update({"line_count": text.count("\n") + (1 if text else 0), "phase_marker_count": len(PHASE_RE.findall(text)), "main_guard_lines": [], "imports": [], "top_level_definitions": {}, "duplicate_top_level_definitions": {}, "duplicate_scoped_definitions": {}, "syntax_error": None})
        try:
            tree = ast.parse(text, filename=rel, type_comments=True)
            row["top_level_definitions"] = top_level_definitions(tree)
            row["duplicate_top_level_definitions"] = {k: v for k, v in row["top_level_definitions"].items() if len(v) > 1}
            row["duplicate_scoped_definitions"] = scoped_duplicates(tree)
            row["main_guard_lines"] = [n.lineno for n in tree.body if isinstance(n, ast.If) and isinstance(n.test, ast.Compare) and isinstance(n.test.left, ast.Name) and n.test.left.id == "__name__" and len(n.test.comparators) == 1 and isinstance(n.test.comparators[0], ast.Constant) and n.test.comparators[0].value == "__main__"]
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(resolve_import(alias.name, path, roots, stdlib) for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append(resolve_import("." * node.level + (node.module or ""), path, roots, stdlib))
            unique = {(v["module"], v["classification"], v["resolved_path"]): v for v in imports}
            row["imports"] = sorted(unique.values(), key=lambda v: (v["module"], v["classification"]))
        except SyntaxError as exc:
            row["syntax_error"] = {"line": exc.lineno, "column": exc.offset, "message": exc.msg}
            findings.append({"rule_id": "python_syntax_error", "severity": "high", "path": rel, "line": exc.lineno or 1, "confidence": "high"})
        findings.extend(security_findings(text, rel))
        if TEST_RE.search(rel):
            row["is_test_file"] = True
            try:
                t = ast.parse(text, filename=rel)
                row["test_functions"] = sorted(n.name for n in ast.walk(t) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_"))
            except SyntaxError:
                row["test_functions"] = []
    elif suffix in TEXT_EXTS or path.name in {".env", ".env.example", "Dockerfile"}:
        if not link:
            try:
                text = raw.decode("utf-8")
                row["line_count"] = text.count("\n") + (1 if text else 0)
                findings.extend(security_findings(text, rel))
            except UnicodeDecodeError:
                pass
    return row, findings


def build_report(root: Path, commit: str | None = None) -> dict[str, Any]:
    root = root.resolve()
    files, findings = [], []
    roots = [root / "src", root]
    stdlib = set(getattr(sys, "stdlib_module_names", set()))
    for path in discover_files(root):
        row, found = scan_file(path, root, roots, stdlib)
        files.append(row)
        findings.extend(found)
    python_files = [f for f in files if f.get("extension") == ".py"]
    syntax_errors, test_files, test_functions = [], [], []
    cross_symbols: dict[str, list[dict[str, Any]]] = defaultdict(list)
    external_imports: dict[str, set[str]] = defaultdict(set)
    unresolved_relative = []
    duplicate_file_count = duplicate_symbol_count = 0
    phases = {}
    for f in python_files:
        if f.get("syntax_error"):
            syntax_errors.append({"path": f["path"], **f["syntax_error"]})
        if f.get("duplicate_top_level_definitions") or f.get("duplicate_scoped_definitions"):
            duplicate_file_count += 1
            duplicate_symbol_count += len(f.get("duplicate_top_level_definitions", {})) + len(f.get("duplicate_scoped_definitions", {}))
        phases[f["path"]] = f.get("phase_marker_count", 0)
        if f.get("is_test_file"):
            test_files.append(f["path"])
            test_functions.extend({"path": f["path"], "name": n} for n in f.get("test_functions", []))
        for name, locations in f.get("top_level_definitions", {}).items():
            cross_symbols[name].extend({"path": f["path"], "line": ln} for ln in locations)
        for imp in f.get("imports", []):
            module = imp["module"].lstrip(".").split(".", 1)[0]
            if imp["classification"] == "external_or_unresolved" and module:
                external_imports[module].add(f["path"])
            if imp["classification"] == "relative_unresolved":
                unresolved_relative.append({"path": f["path"], "module": imp["module"]})
    cross_duplicates = {n: rows for n, rows in sorted(cross_symbols.items()) if len({x["path"] for x in rows}) > 1}
    deps = declared_dependencies(root)
    declared = set(deps.get("declared", []))
    candidates = {}
    for module, paths in sorted(external_imports.items()):
        normalized = module.lower().replace("_", "-")
        candidates[module] = {"paths": sorted(paths), "matches_declared_dependency": normalized in declared or module.lower() in {"pytest", "setuptools"}}
    levels = Counter(x["severity"] for x in findings)
    return {
        "schema": SCHEMA, "repository": "hasnatahmd21/AI-cyber", "audited_commit": commit or git_commit(root),
        "audit_mode": "read_only_static_inventory",
        "limitations": [
            "Static pattern hits are review indicators, not proof of exploitability.",
            "Import resolution is static and cannot fully resolve dynamic imports, runtime registration, plugins, or conditional imports.",
            "Test-file inventory is not a coverage percentage; use instrumented coverage measurement for that claim.",
            "Syntax errors prevent AST-derived imports and symbols from being complete for the affected file; hashes and line-based indicators remain available.",
        ],
        "summary": {
            "tracked_file_count": len(files), "python_file_count": len(python_files), "total_bytes": sum(f["bytes"] for f in files),
            "syntax_error_file_count": len(syntax_errors), "files_with_duplicate_definitions": duplicate_file_count,
            "duplicate_symbol_scopes_count": duplicate_symbol_count, "cross_file_duplicate_symbol_count": len(cross_duplicates),
            "security_indicator_count": len(findings), "security_indicator_severity_counts": {k: levels.get(k, 0) for k in ("critical", "high", "medium", "low")},
            "test_file_count": len(test_files), "test_function_count": len(test_functions), "phase_marker_count": sum(phases.values()),
        },
        "dependencies": deps, "external_import_candidates": candidates, "unresolved_relative_imports": unresolved_relative,
        "syntax_errors": syntax_errors, "cross_file_duplicate_definitions": cross_duplicates, "security_indicators": findings,
        "test_inventory": {"files": sorted(test_files), "functions": sorted(test_functions, key=lambda x: (x["path"], x["name"])), "coverage_percent": None},
        "phase_marker_counts_by_python_file": phases, "files": files,
    }


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "# Stage 0 Forensic Audit Report", "",
        f"- Schema: {report['schema']}", f"- Repository: {report['repository']}",
        f"- Audited commit: {report.get('audited_commit') or 'unavailable (not a Git checkout)'}",
        "- Mode: read-only static inventory; no source edits", "",
        "## Inventory summary", "", "| Measure | Result |", "|---|---:|",
        f"| Tracked files | {s['tracked_file_count']} |", f"| Python files | {s['python_file_count']} |",
        f"| Total tracked bytes | {s['total_bytes']:,} |", f"| Syntax-error files | {s['syntax_error_file_count']} |",
        f"| Files with duplicate definitions | {s['files_with_duplicate_definitions']} |",
        f"| Cross-file duplicate symbol names | {s['cross_file_duplicate_symbol_count']} |",
        f"| Static security indicators | {s['security_indicator_count']} |",
        f"| Test files / test functions | {s['test_file_count']} / {s['test_function_count']} |",
        f"| Phase markers | {s['phase_marker_count']} |", "",
        "This is an evidence report, not a claim that the product is secure or that every test passes.",
        "Discovered syntax errors and security indicators are recorded rather than silently repaired. SHA-256 values and detailed locations are in the JSON report.", "",
        "## Syntax errors", ""
    ]
    if report["syntax_errors"]:
        lines += ["| File | Line | Column | Error |", "|---|---:|---:|---|"]
        lines.extend(f"| {x['path'].replace('|', '\\|')} | {x.get('line') or ''} | {x.get('column') or ''} | {str(x.get('message', '')).replace('|', '\\|')} |" for x in report["syntax_errors"])
    else:
        lines.append("No Python syntax errors were observed in the tracked Python files.")
    lines.extend(["", "## Security indicators", ""])
    counts = Counter(x["rule_id"] for x in report["security_indicators"])
    if counts:
        lines.extend(["| Indicator | Count |", "|---|---:|"])
        lines.extend(f"| {name} | {count} |" for name, count in sorted(counts.items()))
        lines.append("Secret-like values are never emitted; severity and locations are in the JSON report.")
    else:
        lines.append("No configured indicators were detected; that is not proof of absence of vulnerabilities.")
    lines.extend(["", "## Dependency and test evidence", ""])
    lines.append("Declared dependencies: " + (", ".join(report["dependencies"].get("declared", [])) or "none parsed"))
    lines.append("")
    candidates = report.get("external_import_candidates", {})
    if candidates:
        lines.append("External/unresolved import candidates (may include optional or development imports):")
        lines.extend(f"- {name}: {'declared candidate' if row['matches_declared_dependency'] else 'not matched to declared dependencies'}; files: {', '.join(row['paths'])}" for name, row in candidates.items())
    else:
        lines.append("No external/unresolved import candidates were derived from AST-readable files.")
    lines.extend(["", f"Test inventory lists {s['test_file_count']} test files and {s['test_function_count']} functions. Coverage percentage is intentionally not reported because AST inventory does not execute tests or measure coverage.", "", "## Limitations", ""])
    lines.extend(f"- {x}" for x in report["limitations"])
    lines.extend(["", "## Re-run", "", "python tools/stage0_audit.py --json-output /tmp/stage0-audit.json --markdown-output /tmp/stage0-audit.md", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()
    report = build_report(args.root)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    markdown = render_markdown(report)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(payload, encoding="utf-8")
    else:
        print(payload)
    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(markdown, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
