#!/usr/bin/env python3
"""Read-only, evidence-producing AST audit for AI-CYBER Stage 0.

The report records source ranges and static relationships. It does not execute
repository code, and risk signals are review leads rather than vulnerability
verdicts. Dynamic dispatch is explicitly reported as a limitation.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
import tomllib
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

SKIP_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules",
    "build", "dist", "site-packages",
}
LEGACY_ROOT_FILES = {
    "Assrf next .py", "HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py",
    "HYDRA_MASTER_RECONSTRUCTED_v2.py", "HYDRA_patched-3.py",
    "IT_tech__MERGED_ALL_FIXES_APPLIED.py", "New tech .py",
}
MARKER_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK|NOT IMPLEMENTED|IMPLEMENT ME)\b", re.I)
RISK_PATTERNS = (
    ("dynamic_execution", re.compile(r"^(eval|exec|compile)$")),
    ("process_or_shell_execution", re.compile(r"^(os\.(system|popen|spawn\w*)|subprocess\.)")),
    ("network_access", re.compile(r"^(socket\.|requests\.|urllib\.|httpx\.|aiohttp\.|websocket|websockets\.|http\.client\.)")),
    ("database_access", re.compile(r"^(sqlite3\.|psycopg|sqlalchemy\.|pymysql\.|mysql\.connector)")),
    ("unsafe_deserialization", re.compile(r"^(pickle\.(load|loads)|dill\.(load|loads)|yaml\.load)$")),
    ("filesystem_mutation", re.compile(r"^(os\.(remove|unlink|replace|rename|mkdir|makedirs|rmdir)|shutil\.(rmtree|move|copy|copy2)|Path\.(write_text|write_bytes|unlink|rename|replace|mkdir|touch))$")),
    ("cryptographic_operation", re.compile(r"^(hashlib\.|hmac\.|cryptography\.|AESGCM$|Ed25519|RSA$|ec\.|padding\.)")),
)
SENSITIVE_IMPORTS = {
    "socket", "requests", "urllib", "httpx", "aiohttp", "websocket",
    "websockets", "subprocess", "pickle", "dill", "cryptography", "ssl",
}
BUILTINS_AND_COMMON_ERRORS = set(
    "print len str int float bool list dict set tuple range enumerate zip sorted sum min max any all "
    "isinstance issubclass super property staticmethod classmethod repr type id open getattr setattr "
    "hasattr callable iter next map filter format vars dir ord chr bytes bytearray object Exception "
    "ValueError TypeError RuntimeError NotImplementedError AssertionError FileNotFoundError KeyError "
    "IndexError StopIteration OSError ImportError NameError AttributeError NotADirectoryError "
    "TimeoutError MemoryError ModuleNotFoundError DeprecationWarning RuntimeWarning Warning".split()
)


def _callee(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _callee(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        base = _callee(node.func)
        return f"{base}(…)" if base else ""
    if isinstance(node, ast.Subscript):
        return _callee(node.value)
    return ""


def _annotation(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except (ValueError, TypeError):
        return None


def _is_main_guard(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
        and len(node.test.ops) == 1
        and isinstance(node.test.ops[0], ast.Eq)
        and len(node.test.comparators) == 1
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value == "__main__"
    )


def _categories(name: str, node: ast.Call) -> list[str]:
    found = [category for category, pattern in RISK_PATTERNS if pattern.search(name)]
    if name in {"open", "io.open"}:
        mode = next(
            (kw.value.value for kw in node.keywords
             if kw.arg == "mode" and isinstance(kw.value, ast.Constant)),
            None,
        )
        if mode is None and len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
            mode = node.args[1].value
        found.append("filesystem_mutation" if isinstance(mode, str) and any(c in mode for c in "wax+") else "filesystem_access")
    if any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords):
        found.append("shell_true")
    if name.endswith((".urlopen", ".urlretrieve")):
        found.append("network_access")
    if name in {"__import__", "importlib.import_module"}:
        found.append("dynamic_import")
    return sorted(set(found))


class _Facts(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.scope: list[str] = []
        self.symbols: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.main_guards: list[int] = []
        self.broad_exceptions: list[dict[str, Any]] = []

    def _symbol(self, node: ast.AST, kind: str, name: str) -> None:
        parent = ".".join(self.scope) or "<module>"
        qualified = name if parent == "<module>" else f"{parent}.{name}"
        args: list[str] = []
        decorators: list[str] = []
        returns = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            args = [arg.arg for arg in (*a.posonlyargs, *a.args)]
            if a.vararg:
                args.append("*" + a.vararg.arg)
            args.extend(arg.arg for arg in a.kwonlyargs)
            if a.kwarg:
                args.append("**" + a.kwarg.arg)
            decorators = [_annotation(d) or "" for d in node.decorator_list]
            returns = _annotation(node.returns)
        elif isinstance(node, ast.ClassDef):
            decorators = [_annotation(d) or "" for d in node.decorator_list]
        doc = ast.get_docstring(node) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else None
        self.symbols.append({
            "kind": kind, "name": name, "scope": parent,
            "qualified_name": qualified, "line_start": getattr(node, "lineno", 0),
            "line_end": getattr(node, "end_lineno", getattr(node, "lineno", 0)),
            "decorators": decorators, "arguments": args, "returns": returns,
            "docstring_summary": doc.splitlines()[0].strip()[:240] if doc else "",
        })

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for part in (*node.decorator_list, *node.bases, *node.keywords):
            self.visit(part)
        self._symbol(node, "class", node.name)
        self.scope.append(node.name)
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for part in node.decorator_list:
            self.visit(part)
        for part in node.args.defaults:
            self.visit(part)
        for part in node.args.kw_defaults:
            if part is not None:
                self.visit(part)
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if arg.annotation:
                self.visit(arg.annotation)
        for arg in (node.args.vararg, node.args.kwarg):
            if arg and arg.annotation:
                self.visit(arg.annotation)
        if node.returns:
            self.visit(node.returns)
        self._symbol(node, "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function", node.name)
        self.scope.append(node.name)
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append({
            "line": node.lineno, "column": node.col_offset,
            "caller": ".".join(self.scope) or "<module>",
            "callee": _callee(node.func) or "<dynamic-expression>",
            "keyword_names": sorted(k.arg for k in node.keywords if k.arg),
            "categories": _categories(_callee(node.func), node),
        })
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append({
                "line": node.lineno, "kind": "import", "module": alias.name,
                "name": None, "alias": alias.asname, "level": 0,
            })

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.imports.append({
                "line": node.lineno, "kind": "from", "module": node.module or "",
                "name": alias.name, "alias": alias.asname, "level": node.level,
            })

    def visit_If(self, node: ast.If) -> None:
        if _is_main_guard(node):
            self.main_guards.append(node.lineno)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        name = _annotation(node.type)
        if node.type is None or name in {"Exception", "BaseException"}:
            suppresses = len(node.body) == 1 and (
                isinstance(node.body[0], ast.Pass)
                or (isinstance(node.body[0], ast.Return) and node.body[0].value is None)
            )
            self.broad_exceptions.append({
                "line": node.lineno, "exception": name or "bare except",
                "suppresses_error": suppresses,
            })
        self.generic_visit(node)



def _unused_import_candidates(tree: ast.AST, rel: str) -> list[dict[str, Any]]:
    """Suggest likely unused imports; wildcard/re-export surfaces are excluded."""
    if Path(rel).name == "__init__.py" or Path(rel).as_posix().endswith("ai_cyber_os/canonical.py"):
        return []
    loaded = {
        node.id for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                if bound not in loaded:
                    found.append({"line": node.lineno, "module": alias.name, "bound_name": bound})
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                if bound not in loaded and not (node.module == "__future__" and alias.name == "annotations"):
                    found.append({
                        "line": node.lineno, "module": ("." * node.level) + (node.module or ""),
                        "imported_name": alias.name, "bound_name": bound,
                    })
    return sorted(found, key=lambda x: (x["line"], x["bound_name"]))


def _stub_candidates(tree: ast.AST) -> list[dict[str, Any]]:
    """Find obviously placeholder-only function bodies, without judging valid None returns."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = list(node.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body = body[1:]
        if len(body) != 1:
            continue
        statement = body[0]
        reason = None
        if isinstance(statement, ast.Pass):
            reason = "pass_only_body"
        elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and statement.value.value is Ellipsis:
            reason = "ellipsis_only_body"
        elif isinstance(statement, ast.Raise) and isinstance(statement.exc, ast.Call):
            if _callee(statement.exc.func) == "NotImplementedError":
                reason = "raises_not_implemented"
        elif isinstance(statement, ast.Raise) and isinstance(statement.exc, ast.Name) and statement.exc.id == "NotImplementedError":
            reason = "raises_not_implemented"
        if reason:
            found.append({
                "name": node.name, "line_start": node.lineno,
                "line_end": getattr(node, "end_lineno", node.lineno), "reason": reason,
            })
    return sorted(found, key=lambda x: (x["line_start"], x["name"]))


def _unreachable_statement_candidates(tree: ast.AST, source_text: str) -> list[dict[str, Any]]:
    """Find obvious statements following unconditional return/raise/break/continue."""
    found: list[dict[str, Any]] = []

    def walk_non_block(node: ast.AST, scope: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = f"{scope}.{node.name}" if scope else node.name
            inspect_block(node.body, name)
            for dec in node.decorator_list:
                walk_non_block(dec, scope)
            return
        if isinstance(node, ast.ClassDef):
            name = f"{scope}.{node.name}" if scope else node.name
            inspect_block(node.body, name)
            return
        for _, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                walk_non_block(value, scope)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, ast.AST):
                        walk_non_block(child, scope)

    def inspect_block(statements: list[ast.stmt], scope: str) -> None:
        stopped = False
        for statement in statements:
            if stopped:
                found.append({
                    "line": getattr(statement, "lineno", 0),
                    "scope": scope or "<module>",
                    "statement_type": type(statement).__name__,
                    "source": (ast.get_source_segment(source_text, statement) or "").splitlines()[0][:200],
                })
            # Scan nested blocks independently; a return inside an if doesn't
            # make the following outer statement unreachable.
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                walk_non_block(statement, scope)
            else:
                for field_name in ("body", "orelse", "finalbody"):
                    block = getattr(statement, field_name, None)
                    if isinstance(block, list) and block and all(isinstance(x, ast.stmt) for x in block):
                        inspect_block(block, scope)
                for handler in getattr(statement, "handlers", []):
                    inspect_block(handler.body, scope)
                for case in getattr(statement, "cases", []):
                    inspect_block(case.body, scope)
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                stopped = True

    if not isinstance(tree, ast.Module):
        return found
    inspect_block(tree.body, "")
    return sorted(found, key=lambda x: (x["line"], x["scope"]))


def _import_findings(
    imports: list[dict[str, Any]],
    path: str,
    module: str | None,
    module_index: dict[str, str],
    declared_dependency_roots: set[str],
) -> list[dict[str, Any]]:
    """Report unresolved local imports and undeclared external roots as candidates."""
    findings = []
    internal_roots = {name.split(".", 1)[0] for name in module_index if "." in name}
    for item in imports:
        imported_module = item["module"]
        root = imported_module.lstrip(".").split(".", 1)[0]
        is_relative = item["kind"] == "from" and item["level"] > 0
        is_internal = root in internal_roots and bool(root)
        if is_relative:
            if module is None:
                continue
            targets = _resolve_imports(module, Path(path).name == "__init__.py", item, module_index)
            if not targets:
                findings.append({
                    "line": item["line"], "kind": "unresolved_relative_import",
                    "module": imported_module, "name": item.get("name"),
                })
            continue
        if is_internal:
            # Imported symbols may be re-exported from a package __init__.py,
            # so only flag an absent module path when the root itself is absent.
            candidates = [imported_module]
            if item.get("name") and item["name"] != "*":
                candidates.append(imported_module + "." + item["name"])
            if not any(candidate in module_index for candidate in candidates) and imported_module not in module_index:
                findings.append({
                    "line": item["line"], "kind": "unresolved_internal_import_candidate",
                    "module": imported_module, "name": item.get("name"),
                })
            continue
        if root and root not in sys.stdlib_module_names and root not in declared_dependency_roots:
            if Path(path).parts[0] != "tests":
                findings.append({
                    "line": item["line"], "kind": "undeclared_external_dependency_candidate",
                    "module": imported_module, "name": item.get("name"),
                })
    return sorted(findings, key=lambda x: (x["line"], x["kind"], x["module"]))


def _module_name(path: Path, root: Path) -> str | None:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts or not all(p.isidentifier() for p in parts):
        return None
    return ".".join(parts)


def _walk_repository(root: Path) -> tuple[list[Path], list[str]]:
    """Walk repository-owned paths without descending through directory symlinks."""
    files: list[Path] = []
    directories: set[str] = set()
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        traversable: list[str] = []
        for dirname in sorted(dirnames):
            if dirname in SKIP_DIRS:
                continue
            candidate = current_path / dirname
            if candidate.is_symlink():
                # Inventory the link itself; never recurse through it.
                files.append(candidate)
            else:
                traversable.append(dirname)
                directories.add(candidate.relative_to(root).as_posix())
        dirnames[:] = traversable
        for filename in filenames:
            files.append(current_path / filename)
    files.sort(key=lambda p: p.relative_to(root).as_posix())
    return files, sorted(directories)


def _python_files(root: Path) -> list[Path]:
    return [path for path in _walk_repository(root)[0] if path.suffix.lower() == ".py"]


def _resolve_imports(module: str, package_file: bool, item: dict[str, Any], modules: dict[str, str]) -> set[str]:
    base, level, name = item["module"], item["level"], item["name"]
    if item["kind"] == "import":
        candidates = [base]
    elif level:
        package = module if package_file else module.rpartition(".")[0]
        parts = package.split(".") if package else []
        keep = max(0, len(parts) - level + 1)
        prefix = ".".join(parts[:keep])
        joined = ".".join(p for p in (prefix, base) if p)
        candidates = [joined] if joined else []
        if name and name != "*":
            candidates.append(".".join(p for p in (joined, name) if p))
    else:
        candidates = [base]
        if name and name != "*":
            candidates.append(".".join(p for p in (base, name) if p))
    return {modules[candidate] for candidate in candidates if candidate in modules}


def _entrypoint_modules(root: Path) -> dict[str, list[str]]:
    found: dict[str, list[str]] = defaultdict(list)
    pyproject = root / "pyproject.toml"
    if pyproject.is_file() and not pyproject.is_symlink():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            scripts = data.get("project", {}).get("scripts", {})
            if isinstance(scripts, dict):
                for script, target in sorted(scripts.items()):
                    if isinstance(target, str) and ":" in target:
                        module, function = target.split(":", 1)
                        found[module].append(f"{script} -> {function}")
        except (OSError, tomllib.TOMLDecodeError):
            pass
    found["ai_cyber_os.__main__"].append("python -m ai_cyber_os")
    found["ai_cyber_os.ui"].append("local UI module")
    return {k: sorted(set(v)) for k, v in sorted(found.items())}



def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Hash file contents incrementally; for symlinks hash only the link target text."""
    digest = hashlib.sha256()
    if path.is_symlink():
        digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        return digest.hexdigest()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _metadata_preview(value: Any) -> Any:
    """Keep report metadata useful and bounded without copying nested manifest data."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:300]
    if isinstance(value, list):
        return {
            "kind": "list",
            "length": len(value),
            "sample_types": sorted({type(item).__name__ for item in value[:20]}),
        }
    if isinstance(value, dict):
        keys = sorted(str(key) for key in value)
        return {"kind": "object", "length": len(value), "keys": keys[:50]}
    return {"kind": type(value).__name__}


def _repository_inventory(root: Path) -> dict[str, Any]:
    """Inventory every repository file/directory without dumping dataset contents."""
    files_on_disk, directory_names = _walk_repository(root)
    directories = set(directory_names)
    records: list[dict[str, Any]] = []
    hashes: dict[str, list[str]] = defaultdict(list)
    counts: dict[str, int] = defaultdict(int)
    package_contract: dict[str, Any] = {}
    manifest_contracts: list[dict[str, Any]] = []
    workflow_contracts: list[dict[str, Any]] = []
    config_categories = {
        "package_configuration", "repository_configuration", "ci_configuration", "ci_workflow",
        "dataset_manifest", "evaluation_fixture", "configuration_or_manifest",
    }
    paths = files_on_disk
    for path in sorted(paths, key=lambda p: p.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower() or ("dotfile" if path.name.startswith(".") else "")
        parts = Path(rel).parts
        if path.is_symlink():
            category = "symlink"
        elif rel in LEGACY_ROOT_FILES:
            category = "legacy_forensic_source"
        elif rel == "pyproject.toml":
            category = "package_configuration"
        elif path.name in {".gitignore", ".gitattributes"}:
            category = "repository_configuration"
        elif rel.startswith(".github/workflows/"):
            category = "ci_workflow"
        elif rel.startswith(".github/"):
            category = "ci_configuration"
        elif rel.startswith("datasets/raw/"):
            category = "raw_dataset_artifact"
        elif rel.startswith("datasets/manifests/"):
            category = "dataset_manifest"
        elif rel.startswith("datasets/acquisition_reports/"):
            category = "acquisition_report"
        elif rel.startswith(("evaluation/", "datasets/evaluation/")):
            category = "evaluation_fixture"
        elif rel.startswith("docs/") or path.name.lower().startswith("readme") or path.name == "RECONSTRUCTION.md":
            category = "documentation"
        elif suffix == ".py":
            category = "python_source"
        elif suffix in {".toml", ".yaml", ".yml", ".ini", ".cfg", ".json", ".jsonl", ".env"}:
            category = "configuration_or_manifest"
        elif suffix in {".gz", ".zip", ".tgz", ".tar", ".bz2", ".xz", ".whl"}:
            category = "compressed_or_binary_artifact"
        else:
            category = "other_file"
        digest = _sha256_file(path)
        hashes[digest].append(rel)
        size = path.lstat().st_size if path.is_symlink() else path.stat().st_size
        counts[category] += 1

        metadata: dict[str, Any] = (
            {"kind": "symlink", "hash_basis": "link_target_text"}
            if path.is_symlink() else {}
        )
        # Parse only small, known configuration/evaluation/manifest surfaces.
        # Large/raw security datasets are hashed, not loaded into this auditor.
        if rel == "pyproject.toml" and not path.is_symlink():
            try:
                raw = path.read_bytes()
                project = tomllib.loads(raw.decode("utf-8"))
                block = project.get("project", {})
                package_contract = {
                    "name": block.get("name"),
                    "version": block.get("version"),
                    "requires_python": block.get("requires-python"),
                    "dependencies": block.get("dependencies", []),
                    "scripts": block.get("scripts", {}),
                    "build_system": project.get("build-system", {}),
                    "pytest_ini_options": project.get("tool", {}).get("pytest", {}).get("ini_options", {}),
                }
                metadata = {"kind": "python-package-contract", "fields": sorted(block)}
            except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                metadata = {"parse_error": str(exc)}
        elif not path.is_symlink() and (category in {"dataset_manifest", "evaluation_fixture"} or rel == "docs/FORENSIC_BASELINE.json"):
            if size <= 5_000_000 and suffix == ".json":
                raw = path.read_bytes()
                try:
                    payload = json.loads(raw.decode("utf-8"))
                    if isinstance(payload, dict):
                        selected = (
                            "dataset", "version", "source", "license", "sha256",
                            "record_count", "schema", "ingestion_status", "validation_status",
                            "canonical_runtime", "logical_phases", "canonicalization_status",
                            "repository", "repair_branch", "public_entrypoints",
                        )
                        metadata = {
                            "kind": "json-contract",
                            "top_level_key_count": len(payload),
                            "top_level_keys": sorted(str(key) for key in payload)[:200],
                            "selected_fields": {k: _metadata_preview(payload[k]) for k in selected if k in payload},
                            "artifact_count": len(payload.get("artifacts", [])) if isinstance(payload.get("artifacts"), list) else None,
                            "entry_count": len(payload.get("cases", payload.get("records", []))) if isinstance(payload.get("cases", payload.get("records", [])), list) else None,
                        }
                        if category == "dataset_manifest":
                            manifest_contracts.append({"path": rel, **metadata})
                    elif isinstance(payload, list):
                        metadata = {"kind": "json-list", "entry_count": len(payload)}
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    metadata = {"parse_error": str(exc)}
        elif category == "ci_workflow" and not path.is_symlink():
            try:
                raw = path.read_bytes()
                text = raw.decode("utf-8")
                run_lines = []
                for line_number, line in enumerate(text.splitlines(), 1):
                    stripped = line.strip()
                    if (
                        stripped.startswith(("uses:", "run:", "on:", "push:", "pull_request:", "workflow_dispatch:", "schedule:"))
                        or "python-version:" in stripped
                    ):
                        run_lines.append({"line": line_number, "text": stripped[:300]})
                metadata = {"kind": "workflow-static-directives", "directives": run_lines}
                workflow_contracts.append({"path": rel, **metadata})
            except UnicodeDecodeError:
                metadata = {"kind": "non-utf8-workflow"}
        sensitive_name = path.name.lower() in {
            ".env", ".env.local", "id_rsa", "id_ed25519", "credentials.json",
            "service-account.json", "private.key", "server.key",
        }
        records.append({
            "path": rel, "category": category, "suffix": suffix,
            "bytes": size, "sha256": digest, "text_extension": suffix in {
                ".py", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".json",
                ".jsonl", ".csv", ".xml", ".md", ".txt", ".html", ".js",
                ".css", ".sh", ".rst",
            },
            "potentially_sensitive_filename": sensitive_name,
            "metadata": metadata,
        })

    duplicate_groups = [
        {"sha256": digest, "paths": sorted(names)}
        for digest, names in sorted(hashes.items()) if len(names) > 1
    ]
    summary = {
        "repository_file_count": len(records),
        "repository_directory_count": len(directories),
        "configuration_and_manifest_file_count": sum(1 for r in records if r["category"] in config_categories),
        "duplicate_content_groups": len(duplicate_groups),
        "category_counts": dict(sorted(counts.items())),
        "potentially_sensitive_named_files": [r["path"] for r in records if r["potentially_sensitive_filename"]],
    }
    return {
        "summary": summary,
        "directories": sorted(directories),
        "files": records,
        "duplicate_content_groups": duplicate_groups,
        "package_contract": package_contract,
        "dataset_manifest_contracts": manifest_contracts,
        "ci_workflow_contracts": workflow_contracts,
    }


def build_report(root: Path) -> dict[str, Any]:
    root = root.resolve()
    repository_inventory = _repository_inventory(root)
    paths = [
        root / item["path"]
        for item in repository_inventory["files"]
        if Path(item["path"]).suffix.lower() == ".py" and item["category"] != "symlink"
    ]
    records: dict[str, dict[str, Any]] = {}
    module_index: dict[str, str] = {}
    manifest_hasher = hashlib.sha256()

    for path in paths:
        rel = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8", errors="replace")
        manifest_hasher.update(rel.encode("utf-8") + b"\0")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                manifest_hasher.update(chunk)
        manifest_hasher.update(b"\0")
        module = _module_name(path, root)
        if module:
            module_index[module] = rel
        try:
            tree = ast.parse(source, filename=rel, type_comments=True)
            facts = _Facts(rel)
            facts.visit(tree)
            syntax_error = None
        except (SyntaxError, ValueError) as exc:
            tree = None
            facts = None
            syntax_error = {
                "line": getattr(exc, "lineno", None),
                "column": getattr(exc, "offset", None),
                "message": getattr(exc, "msg", str(exc)),
                "text": (getattr(exc, "text", None) or "").rstrip("\n")[:300],
            }

        lines = source.splitlines()
        markers = [
            {"line": i, "marker": match.group(1).upper(), "text": line.strip()[:240]}
            for i, line in enumerate(lines, 1)
            for match in [MARKER_RE.search(line)] if match
        ]
        risks: list[dict[str, Any]] = []
        imports = facts.imports if facts else []
        calls = facts.calls if facts else []
        for call in calls:
            for category in call["categories"]:
                risks.append({
                    "line": call["line"], "category": category,
                    "evidence": call["callee"], "scope": call["caller"],
                })
        for imported in imports:
            if imported["module"].split(".", 1)[0] in SENSITIVE_IMPORTS:
                risks.append({
                    "line": imported["line"], "category": "sensitive_import",
                    "evidence": imported["module"], "scope": "<import>",
                })

        duplicates: dict[str, list[int]] = {}
        if facts:
            by_scope: dict[tuple[str, str, str], list[int]] = defaultdict(list)
            for sym in facts.symbols:
                if sym["kind"] in {"class", "function", "async_function"}:
                    by_scope[(sym["scope"], sym["kind"], sym["name"])].append(sym["line_start"])
            duplicates = {
                f"{scope}:{kind}:{name}": sorted(found)
                for (scope, kind, name), found in sorted(by_scope.items()) if len(found) > 1
            }

        parts = Path(rel).parts
        if rel in LEGACY_ROOT_FILES:
            classification = "legacy_forensic_candidate"
        elif parts and parts[0] == "tests":
            classification = "test"
        elif parts and parts[0] == "tools":
            classification = "tooling"
        elif parts and parts[0] == "src":
            classification = "package_source"
        else:
            classification = "other_python"
        records[rel] = {
            "path": rel, "module": module, "classification": classification,
            "bytes": path.stat().st_size, "lines": len(lines), "sha256": _sha256_file(path),
            "syntax_ok": syntax_error is None, "syntax_error": syntax_error,
            "module_docstring": (
                ast.get_docstring(tree).splitlines()[0].strip()[:240]
                if tree is not None and ast.get_docstring(tree) else ""
            ),
            "symbols": facts.symbols if facts else [],
            "imports": imports, "calls": calls,
            "unused_import_candidates": _unused_import_candidates(tree, rel) if tree is not None else [],
            "stub_candidates": _stub_candidates(tree) if tree is not None else [],
            "unreachable_statement_candidates": _unreachable_statement_candidates(tree, source) if tree is not None else [],
            "import_resolution_findings": [],
            "main_guards": facts.main_guards if facts else [],
            "broad_exceptions": facts.broad_exceptions if facts else [],
            "duplicate_scoped_symbols": duplicates,
            "todo_markers": markers,
            "side_effect_signals": sorted(risks, key=lambda x: (x["line"], x["category"], x["evidence"])),
            "static_import_targets": [], "static_call_edges": [],
            "direct_call_targets_without_local_definition": [],
            "no_static_callsite_candidates": [], "tested_by_test_files": [],
        }

    # Resolve module imports and calculate static entrypoint closure.
    file_edges: dict[str, set[str]] = defaultdict(set)
    symbol_locations: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rel, record in records.items():
        for sym in record["symbols"]:
            symbol_locations[f"{sym['kind']}:{sym['name']}"].append({
                "path": rel, "line_start": sym["line_start"], "line_end": sym["line_end"],
            })
        module = record["module"]
        if not module:
            continue
        package_file = Path(rel).name == "__init__.py"
        for imported in record["imports"]:
            file_edges[rel].update(_resolve_imports(module, package_file, imported, module_index))
        record["static_import_targets"] = sorted(file_edges[rel])

    package_contract = _repository_inventory(root)["package_contract"]
    declared_dependency_roots = {
        re.split(r"[<>=!~;]", str(dependency), maxsplit=1)[0].strip()
        .split("[", 1)[0].replace("-", "_").replace(".", "_").lower()
        for dependency in package_contract.get("dependencies", [])
    }
    declared_dependency_roots = {x for x in declared_dependency_roots if x}
    module_names = {record["module"] for record in records.values() if record["module"]}
    for rel, record in records.items():
        record["import_resolution_findings"] = _import_findings(
            record["imports"], rel, record["module"], module_index, declared_dependency_roots
        )

    # Link modules to tests that statically import them; this is association
    # evidence only and does not assert the tests cover every behavior.
    for record in records.values():
        record["tested_by_test_files"] = []
    for test_path, test_record in records.items():
        if test_record["classification"] != "test":
            continue
        for target in test_record["static_import_targets"]:
            if target in records:
                records[target]["tested_by_test_files"].append(test_path)
    for record in records.values():
        record["tested_by_test_files"] = sorted(set(record["tested_by_test_files"]))

    for rel, record in records.items():
        symbols = record["symbols"]
        local_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for sym in symbols:
            local_by_name[sym["name"]].append(sym)
        edges = []
        called_names = set()
        for call in record["calls"]:
            callee = call["callee"]
            candidates: list[dict[str, Any]] = []
            if "." not in callee and callee in local_by_name:
                candidates = local_by_name[callee]
            elif callee.startswith(("self.", "cls.")):
                attr = callee.split(".", 1)[1]
                owner = call["caller"].rsplit(".", 1)[0] if "." in call["caller"] else ""
                candidates = [s for s in symbols if s["name"] == attr and s["scope"] == owner]
            if candidates:
                called_names.add(callee.split(".")[-1])
                for target in candidates:
                    edges.append({
                        "caller": call["caller"], "callee": target["qualified_name"],
                        "line": call["line"],
                        "resolution": "ambiguous-local-name" if len(candidates) > 1 else "local-name-match",
                    })
        record["static_call_edges"] = sorted(edges, key=lambda e: (e["line"], e["caller"], e["callee"]))
        record["direct_call_targets_without_local_definition"] = sorted({
            c["callee"] for c in record["calls"]
            if c["callee"] and "." not in c["callee"]
            and c["callee"] not in local_by_name
            and c["callee"] not in BUILTINS_AND_COMMON_ERRORS
        })
        record["no_static_callsite_candidates"] = [
            {
                "qualified_name": s["qualified_name"],
                "line_start": s["line_start"], "line_end": s["line_end"],
            }
            for s in symbols
            if s["kind"] in {"function", "async_function"}
            and s["name"] not in called_names
            and not s["name"].startswith("_")
            and s["name"] not in {"main", "run", "execute", "handler"}
        ]

    cross_duplicates = {
        key: sorted(entries, key=lambda e: (e["path"], e["line_start"]))
        for key, entries in sorted(symbol_locations.items())
        if len({entry["path"] for entry in entries}) > 1
    }
    entrypoints = _entrypoint_modules(root)
    entry_files: dict[str, list[str]] = defaultdict(list)
    for module, reasons in entrypoints.items():
        if module in module_index:
            entry_files[module_index[module]].extend(reasons)
    core = module_index.get("ai_cyber_os.hydra")
    if core:
        entry_files[core].append("canonical HYDRA core (audit root)")
    reachable = set(entry_files)
    queue = deque(sorted(reachable))
    while queue:
        path = queue.popleft()
        for target in sorted(file_edges.get(path, set())):
            if target not in reachable:
                reachable.add(target)
                queue.append(target)
    for path, record in records.items():
        record["entrypoint_reasons"] = sorted(set(entry_files.get(path, [])))
        record["static_runtime_reachable"] = path in reachable

    summary = {
        "python_file_count": len(paths),
        "syntax_error_file_count": sum(not x["syntax_ok"] for x in records.values()),
        "total_symbols": sum(len(x["symbols"]) for x in records.values()),
        "total_callsites": sum(len(x["calls"]) for x in records.values()),
        "cross_file_duplicate_symbol_keys": len(cross_duplicates),
        "files_with_duplicate_scoped_symbols": sum(bool(x["duplicate_scoped_symbols"]) for x in records.values()),
        "side_effect_signal_count": sum(len(x["side_effect_signals"]) for x in records.values()),
        "todo_marker_count": sum(len(x["todo_markers"]) for x in records.values()),
        "broad_exception_count": sum(len(x["broad_exceptions"]) for x in records.values()),
        "unused_import_candidate_count": sum(len(x["unused_import_candidates"]) for x in records.values()),
        "stub_candidate_count": sum(len(x["stub_candidates"]) for x in records.values()),
        "unreachable_statement_candidate_count": sum(len(x["unreachable_statement_candidates"]) for x in records.values()),
        "import_resolution_finding_count": sum(len(x["import_resolution_findings"]) for x in records.values()),
        "static_runtime_reachable_files": len(reachable),
        "entrypoint_file_count": len(entry_files),
        "legacy_forensic_files_present": sorted(n for n in LEGACY_ROOT_FILES if (root / n).exists()),
        "file_content_manifest_sha256": manifest_hasher.hexdigest(),
        **repository_inventory["summary"],
    }
    return {
        "schema": "ai-cyber.deep-forensic-audit.v1",
        "audit_mode": "read-only static AST analysis",
        "commit_sha": os.environ.get("GITHUB_SHA") or None,
        "entrypoints": entrypoints,
        "entrypoint_files": {
            p: {"path": p, "reasons": sorted(set(reasons))}
            for p, reasons in sorted(entry_files.items())
        },
        "summary": summary,
        "repository_inventory": repository_inventory,
        "limitations": [
            "Static import reachability is approximate; dynamic imports, reflection, callbacks, decorators, registries, environment-driven dispatch and plugin loading can alter runtime reachability.",
            "Call edges resolve statically visible same-file names and self/cls methods only. Cross-file calls through imported objects and dynamic dispatch are not claimed complete.",
            "A security-sensitive signal is a source-pattern review lead, not a confirmed vulnerability.",
            "A function with no static callsite is an investigation candidate, not proof that it is unreachable.",
            "AST inspection does not execute tests or prove external integrations, OS/network isolation, cryptographic trust, deception, or recovery behavior.",
            "Comment markers are searched as text; absence of TODO/FIXME/etc. is not proof of completeness.",
        ],
        "cross_file_duplicate_symbols": cross_duplicates,
        "files": [records[path.relative_to(root).as_posix()] for path in paths],
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    out = [
        "# AI-CYBER Stage 0 — Deep Forensic Audit",
        "",
        f"**Commit:** {report.get('commit_sha') or 'not supplied by runtime environment'}",
        "**Mode:** read-only AST analysis; this is not a runtime security certification.",
        "",
        "## Summary",
        "",
    ]
    for key, label in [
        ("python_file_count", "Python files scanned"),
        ("syntax_error_file_count", "Syntax-error files"),
        ("total_symbols", "Class/function/method symbols"),
        ("total_callsites", "Call sites recorded"),
        ("cross_file_duplicate_symbol_keys", "Cross-file duplicate symbol-name keys"),
        ("files_with_duplicate_scoped_symbols", "Files with same-scope duplicate definitions"),
        ("side_effect_signal_count", "Security-sensitive static signals"),
        ("todo_marker_count", "TODO/FIXME/etc. markers"),
        ("broad_exception_count", "Broad exception handlers"),
        ("unused_import_candidate_count", "Unused import candidates"),
        ("stub_candidate_count", "Stub/placeholder function candidates"),
        ("unreachable_statement_candidate_count", "Unreachable statement candidates"),
        ("import_resolution_finding_count", "Import resolution findings"),
        ("static_runtime_reachable_files", "Files statically reachable from selected entry points"),
        ("entrypoint_file_count", "Entry-point files"),
        ("file_content_manifest_sha256", "File-content manifest SHA-256"),
    ]:
        out.append(f"- {label}: {summary[key]}")
    out += [
        "",
        "Legacy forensic files present: " + (", ".join(summary["legacy_forensic_files_present"]) or "none detected") + ".",
        "",
        "## Repository file, folder, and configuration inventory",
        "",
        f"- Repository files: {summary['repository_file_count']}",
        f"- Directories: {summary['repository_directory_count']}",
        f"- Configuration / manifest files: {summary['configuration_and_manifest_file_count']}",
        f"- Repeated-content groups: {summary['duplicate_content_groups']}",
        f"- Potentially sensitive filenames (names only; contents never disclosed): {len(summary['potentially_sensitive_named_files'])}",
        "",
        "| Path | Category | Bytes | SHA-256 | Metadata summary |",
        "|---|---|---:|---|---|",
        *[
            f"| {item['path']} | {item['category']} | {item['bytes']} | {item['sha256']} | "
            + (json.dumps(item['metadata'].get('selected_fields', item['metadata'].get('kind', '')), sort_keys=True)[:180].replace('|', '\\|') if item['metadata'] else '—')
            + " |"
            for item in report["repository_inventory"]["files"]
        ],
        "",
        "### Directory inventory",
        "",
        *[f"- {folder}/" for folder in report["repository_inventory"]["directories"]],
        "",
        "### Package entry points and dependencies",
        "",
        f"- Package: {report['repository_inventory']['package_contract'].get('name') or 'unknown'}",
        f"- Version: {report['repository_inventory']['package_contract'].get('version') or 'unknown'}",
        f"- Python requirement: {report['repository_inventory']['package_contract'].get('requires_python') or 'unknown'}",
        "- Runtime dependencies: " + ", ".join(report["repository_inventory"]["package_contract"].get("dependencies", [])),
        *[f"- Console script: {name} -> {target}" for name, target in sorted(report["repository_inventory"]["package_contract"].get("scripts", {}).items())],
        "",
        "### CI workflow directives",
        "",
        *[
            f"- {wf['path']}: " + "; ".join(f"L{d['line']} {d['text']}" for d in wf["directives"])
            for wf in report["repository_inventory"]["ci_workflow_contracts"]
        ],
        "",
        "### Dataset manifest contracts",
        "",
        *[
            f"- {mf['path']}: keys={', '.join(mf.get('top_level_keys', []))}; "
            f"selected={json.dumps(mf.get('selected_fields', {}), sort_keys=True)[:400]}"
            for mf in report["repository_inventory"]["dataset_manifest_contracts"]
        ],
        "",
        "## File-by-file inventory",
        "",
        "| Path | Classification | Syntax | Bytes | Lines | Symbols | Calls | Static runtime | Main guards | Risk categories | Markers |",
        "|---|---|---:|---:|---:|---:|---:|---|---:|---|---:|",
    ]
    for item in report["files"]:
        categories = sorted({s["category"] for s in item["side_effect_signals"]})
        out.append(
            f"| {item['path']} | {item['classification']} | {'OK' if item['syntax_ok'] else 'ERROR'} | "
            f"{item['bytes']} | {item['lines']} | {len(item['symbols'])} | {len(item['calls'])} | "
            f"{'yes' if item['static_runtime_reachable'] else 'no'} | {len(item['main_guards'])} | "
            f"{', '.join(categories) or '—'} | {len(item['todo_markers'])} |"
        )
    out += ["", "## Symbol and finding appendix", ""]
    for item in report["files"]:
        out += [
            f"### {item['path']}", "",
            f"SHA-256: {item['sha256']} · static runtime reachability: {'yes' if item['static_runtime_reachable'] else 'no'}",
            "",
        ]
        if item["syntax_error"]:
            e = item["syntax_error"]
            out.append(f"- **Syntax error:** line {e['line']}, column {e['column']}: {e['message']}")
        if item["module_docstring"]:
            out.append(f"- Module purpose: {item['module_docstring']}")
        if item["symbols"]:
            out.append("- Definitions:")
            for symbol in item["symbols"]:
                suffix = f" — {symbol['docstring_summary']}" if symbol["docstring_summary"] else ""
                out.append(
                    f"  - {symbol['kind']} {symbol['qualified_name']} "
                    f"(L{symbol['line_start']}-L{symbol['line_end']}){suffix}"
                )
        if item["import_resolution_findings"]:
            out.append("- **Import resolution candidates (review before treating as errors):**")
            for finding in item["import_resolution_findings"]:
                out.append(f"  - L{finding['line']}: {finding['kind']} — {finding['module']} {finding.get('name') or ''}")
        if item["unused_import_candidates"]:
            out.append("- Unused import candidates (re-exports/dynamic use can be false positives):")
            for finding in item["unused_import_candidates"]:
                out.append(f"  - L{finding['line']}: {finding['module']} -> {finding['bound_name']}")
        if item["stub_candidates"]:
            out.append("- **Stub/placeholder function candidates:**")
            for finding in item["stub_candidates"]:
                out.append(f"  - {finding['name']} (L{finding['line_start']}-L{finding['line_end']}): {finding['reason']}")
        if item["unreachable_statement_candidates"]:
            out.append("- Unreachable statement candidates (within the same unconditional block):")
            for finding in item["unreachable_statement_candidates"]:
                out.append(f"  - L{finding['line']} in {finding['scope']}: {finding['statement_type']} — {finding['source']}")
        if item["duplicate_scoped_symbols"]:
            out.append("- **Same-scope duplicate definitions (inspect source ranges):**")
            for name, lines in sorted(item["duplicate_scoped_symbols"].items()):
                out.append(f"  - {name}: lines {', '.join(map(str, lines))}")
        if item["side_effect_signals"]:
            out.append("- Security-sensitive static signals (review in context):")
            for signal in item["side_effect_signals"]:
                out.append(f"  - L{signal['line']}: {signal['category']} — {signal['evidence']} [scope: {signal['scope']}]")
        if item["broad_exceptions"]:
            out.append("- Broad exception handlers:")
            for e in item["broad_exceptions"]:
                out.append(f"  - L{e['line']}: {e['exception']}; suppresses_error={e['suppresses_error']}")
        if item["todo_markers"]:
            out.append("- TODO/FIXME/etc. markers:")
            for marker in item["todo_markers"]:
                out.append(f"  - L{marker['line']}: {marker['marker']} — {marker['text']}")
        if item["main_guards"]:
            out.append("- Main guards: " + ", ".join(f"L{x}" for x in item["main_guards"]))
        if item["entrypoint_reasons"]:
            out.append("- Entry point: " + ", ".join(item["entrypoint_reasons"]))
        if item["tested_by_test_files"]:
            out.append("- Tests with direct static import references (not a coverage verdict): " + ", ".join(item["tested_by_test_files"]))
        if item["static_import_targets"]:
            out.append("- Statically resolved internal imports: " + ", ".join(item["static_import_targets"]))
        if item["static_call_edges"]:
            out.append("- Same-file static call edges:")
            for edge in item["static_call_edges"]:
                out.append(f"  - L{edge['line']}: {edge['caller']} -> {edge['callee']} ({edge['resolution']})")
        if item["no_static_callsite_candidates"]:
            out.append("- Public-function candidates with no same-file call edge (not proof of dead code):")
            for candidate in item["no_static_callsite_candidates"]:
                out.append(f"  - {candidate['qualified_name']} (L{candidate['line_start']}-L{candidate['line_end']})")
        out.append("")
    out += ["## Cross-file duplicate symbol names", "",
            "A name collision is not necessarily a semantic duplicate. Do not merge or delete code based on name alone.", ""]
    if report["cross_file_duplicate_symbols"]:
        for key, entries in report["cross_file_duplicate_symbols"].items():
            out.append(f"- **{key}**")
            for entry in entries:
                out.append(f"  - {entry['path']} (L{entry['line_start']}-L{entry['line_end']})")
    else:
        out.append("No cross-file duplicate symbol names found.")
    out += ["", "## Interpretive limits", "", *[f"- {x}" for x in report["limitations"]], "",
            "## Decision", "",
            "This audit report is evidence for review, not an automatic GREEN gate. Source ranges, collisions, risky APIs, syntax issues, unresolved dynamic edges, and high-impact paths require targeted review and tests before refactoring.",
            ""]
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    report = build_report(args.root.resolve())
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
    if args.summary_only:
        print(json.dumps({"commit_sha": report.get("commit_sha"), "summary": report["summary"],
                          "entrypoints": report["entrypoints"]}, indent=2, sort_keys=True))
    elif not args.json_out and not args.markdown_out:
        print(render_markdown(report))
    else:
        print(json.dumps({"commit_sha": report.get("commit_sha"), "summary": report["summary"],
                          "json_out": str(args.json_out) if args.json_out else None,
                          "markdown_out": str(args.markdown_out) if args.markdown_out else None},
                         indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
