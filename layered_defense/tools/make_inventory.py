"""Gate 0: legacy inventory. Produces docs/LEGACY_INVENTORY.md and ai_cyber/legacy/symbol_map.json
(legacy symbol -> new module -> dependencies -> callers -> tests -> verification status)."""
import ast, glob, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from ai_cyber.hydra import Hydra

h = Hydra(); res = {r.phase: r for r in h.run_all()}
rows, md = [], ["# Gate 0 - Legacy inventory\n",
    f"Source: `IT_tech__MERGED_ALL_FIXES_APPLIED.py` ({h.manifest['source_lines']} lines, sha256 `{h.manifest['source_sha256'][:16]}...`)\n",
    "| Phase | File | Classes | Functions | Imports | SQLite | File I/O | `__main__` entry | Tests |", "|---|---|---|---|---|---|---|---|---|"]
for ph, fn in sorted(h.phase_files().items()):
    src = open(os.path.join(h.phases_dir, fn), encoding="utf-8").read(); tree = ast.parse(src)
    classes = [n.name for n in tree.body if isinstance(n, ast.ClassDef)]
    funcs = [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    imps = sorted({(n.module if isinstance(n, ast.ImportFrom) else a.name).split(".")[0]
                   for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in (n.names if isinstance(n, ast.Import) else [None])})
    main = any(isinstance(n, ast.If) and isinstance(n.test, ast.Compare) and getattr(n.test.left, "id", "") == "__name__" for n in tree.body)
    r = res[ph]; status = "verified" if r.ok else "FAILED"
    md.append(f"| {ph} | `{fn}` | {len(classes)} | {len(funcs)} | {', '.join(imps)} | {'yes' if 'sqlite3' in imps else '-'} | "
              f"{'yes' if 'open(' in src else '-'} | {'yes' if main else '-'} | {r.passed} passed / {r.failed} failed |")
    for s in classes + funcs:
        rows.append(dict(legacy_symbol=f"phase_{ph:02d}.{s}", new_module=f"ai_cyber/legacy/hydra_phases/{fn} (preserved unchanged; exposed via ai_cyber/hydra.py)",
                         dependencies=imps, callers=["ai_cyber.hydra.Hydra", f"{fn}::_run_all_tests"] if s != "_run_all_tests" else ["__main__ block"],
                         tests=[f"{fn} built-in suite", "tests/test_hydra_integration.py"], verification_status=status))
md += ["", f"Total symbols mapped: {len(rows)}.", "",
       "## Findings",
       "- Spec says 27 phases; the file actually contains **42 phase modules** (43 segments: Phase 3 appears twice, byte-identical). All 42 preserved; the duplicate is stored once and recorded in `split_manifest.json`.",
       "- Phases are independent single-file modules (own contracts/stores/tests); there is no cross-phase import. In the monolith they shared one namespace and one `from __future__ import annotations`; Phase 13 relied on that (it used `Sequence` before importing it) so each split file received that one line (recorded in the manifest; stripped on reassembly check).",
       "- Alternate entry points: every phase file has an `if __name__ == '__main__'` test runner. Canonical entry is `python -m ai_cyber`.",
       "- Shared mutable state / side effects: phases use in-memory and SQLite stores created by the caller; no network access."]
os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
open(os.path.join(ROOT, "docs", "LEGACY_INVENTORY.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")
json.dump(rows, open(os.path.join(ROOT, "ai_cyber", "legacy", "symbol_map.json"), "w"), indent=1)
print(len(rows), "symbols;", sum(1 for r in res.values() if r.ok), "/ 42 phases verified")
