# Stage 0 — Repository Forensic Audit

**Canonical tool:** tools/forensic_deep_audit.py  
**Output:** GitHub Actions artifact named forensic-stage0-<commit SHA>  
**Scope:** read-only inspection; no root monolith is rewritten or merged.

## Audit method

The deep audit inventories every repository file and directory present in a clean checkout (excluding common virtual-environment/build/cache folders), recording path, category, byte size and SHA-256. For every parsable Python file it additionally records line ranges, module purpose, every class/function/method, imports, callsites and keyword arguments, same-file statically resolved call edges, main guards, same-scope duplicate definitions, broad exception handlers, side-effect/security-sensitive API signals, TODO/FIXME/HACK markers, entry-point classification, approximate import reachability from package entry points, and direct static test-file-to-module import associations. It extracts the declared package scripts/dependencies, CI workflow directives, and selected fields from small dataset manifests and evaluation fixtures. Large raw dataset contents are hashed but not parsed or copied into reports.

It also records repeated symbol names across files and generates a deterministic file-content manifest hash. The JSON artifact is the machine-readable source of truth; the Markdown artifact provides repository-wide file/folder inventory, configuration/manifest summary, and Python symbol/call-site listings. Each artifact records the commit SHA supplied by GitHub Actions.

## Known forensic source groups

### Preserved root-level legacy sources

- Assrf next .py — SSRF-oriented historical source.
- HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py
- HYDRA_MASTER_RECONSTRUCTED_v2.py
- HYDRA_patched-3.py
- IT_tech__MERGED_ALL_FIXES_APPLIED.py
- New tech .py

These files are not selected as runtime code solely by their names. Keep them intact until their symbol provenance, caller relationships, side effects, and equivalence with the canonical package have been assessed.

### Canonical package

The repair branch designates src/ai_cyber_os/hydra.py as the single core HYDRA phase implementation. Supporting modules cover CLI/UI, command gateway, operations/report state, telemetry, local red-team checks, datasets/manifests, the SQLite/FTS5 knowledge store, RAG, source parsers, relationships, and security evaluation. The detailed file tree, symbol ranges, and static import reachability are emitted afresh by the audit tool rather than hand-maintained.

### Verification and tooling

- tests/ contains unit/integration contracts; the audit reports which modules are imported or tested statically but does not infer test coverage from filenames alone.
- tools/ contains audit, dataset, evaluation, and adversarial harness scripts.
- .github/workflows/reconstruction.yml is the primary reconstruction CI workflow. It runs compile checks, the quick inventory, the complete pytest suite, data/RAG evaluation gates, CLI and wheel smoke tests, the controlled adversarial harness, the HYDRA phases, and final hardening.

## Reading the report correctly

- Static import reachability is an approximation; dynamic imports, reflection, callback registration, decorators, environment-based dispatch, and plugins can change runtime behavior.
- A same-name symbol is not necessarily a duplicate implementation. Compare body semantics, callers, side effects, serialization/data contracts, and relevant tests.
- A function with no observed same-file caller is only an investigation candidate, not proof of dead code.
- A sensitive API marker is not automatically a vulnerability; record the line and review the context and trust boundary.
- Static AST analysis cannot prove live SSRF prevention, real network isolation, signed artifact verification, isolated deception, or compromise-to-regeneration recovery.
- Syntax-error evidence is recorded instead of suppressing the rest of the inventory. A report is expected to expose defects, not turn them into a success claim.

## Stage 0 completion gates

Stage 0 is eligible for acceptance only after:

1. The deep audit artifact is generated from the exact branch commit.
2. Its summary and syntax-error/duplicate/risk findings are reviewed, not merely counted.
3. Canonical entry points and the core HYDRA module are reconciled with actual static import/call evidence.
4. All six legacy monoliths are individually catalogued by hash, source-line ranges, symbols, duplicates, entry-point guards, imports, side effects, unused-import candidates, stubs, obvious dead statements and TODO markers.
5. Any suspicious/missing syntax or dynamic edges are recorded as UNKNOWN or BLOCKED rather than guessed.
6. The Stage 1 architecture map's assertions and gaps are cross-checked against these outputs.
7. The Stage 0-specific tests and the full reconstruction CI workflow pass on the same commit.

Until these gates are met, use **INVENTORY GENERATED / REVIEW PENDING**, not GREEN.
