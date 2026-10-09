# Stage 0 — Forensic Repository Audit

## Purpose and boundary

Stage 0 establishes a reproducible evidence baseline for hasnatahmd21/AI-cyber. It is read-only with respect to application and legacy source: it inventories what exists, records defects as findings, and does not silently repair, merge, delete, or bless any implementation as canonical. Architecture selection and code repair remain later-stage work.

## Checks performed

The tools/stage0_audit.py program inventories Git-tracked files and computes a SHA-256 for each tracked file. For Python files it records byte/line counts, syntax results, top-level and scoped duplicate declarations, import candidates and static phase markers. Across Python files it builds cross-file duplicate-name and import/dependency candidate indexes. It inventories test files and test functions without presenting that count as a coverage percentage. A static scan records suspicious hard-coded secrets, embedded private-key markers, disabled TLS verification, shell execution, dynamic code execution, pickle deserialization, unsafe YAML loading indicators, weak-crypto indicators, and plaintext HTTP URL indicators. Secret-like values are never copied into the report.

The GitHub Actions workflow runs fixture tests for the audit tool, emits JSON and Markdown reports as a revision-specific artifact, records project pytest results, compiles the canonical package, and records the 27-phase runtime and final-hardening checks. Artifact retention is 90 days.

## Interpretation rules

- A SHA-256 is identity evidence for the bytes observed at the audited commit; it does not prove code safety.
- Duplicate names are candidates for manual behavioral comparison, not automatic proof of equivalence or dead code.
- Static security indicators can be false positives and must be reviewed in context. Absence of a hit is not proof of absence of a vulnerability.
- An AST parse error makes AST-derived information incomplete for that file. The inventory still records its bytes/hash and line-based indicators.
- Import/dependency mapping is static; optional imports, plugin registration, conditional paths, dynamic imports and runtime monkey-patching may not be resolved.
- Test-file/function inventory is not code coverage. Coverage percentage requires executing tests under a coverage instrument.
- CI runtime/test outcomes are evidence only for the exact SHA reported by that run.

## Stage 0 exit criteria

Stage 0 is considered evidence-complete when all of the following are present for the same exact source commit:

1. A complete tracked-file manifest with SHA-256 hashes.
2. Syntax result and duplicate-definition inventory for every AST-readable Python file, with parse failures enumerated.
3. Static import and declared-dependency candidates, including unresolved/ambiguous imports explicitly recorded.
4. Security-sensitive code indicators with rule, severity, file, and line, without exposing credential contents.
5. Test-file and test-function inventory, a clear statement that this is not a coverage percentage, and captured test-run output.
6. Captured compile, project-test, 27-phase runtime and final-hardening results.
7. A report artifact tied to the audited Git commit and reviewed for completeness.

A red code-health finding does not invalidate that the forensic audit ran; it prevents claiming the application is healthy. Findings requiring implementation changes are passed into later stages with their evidence, not hidden to make Stage 0 appear green.

## Re-run

python tools/stage0_audit.py --json-output /tmp/stage0-forensic-audit.json --markdown-output /tmp/stage0-forensic-audit.md
python -m pytest -q tests/test_stage0_audit.py

Run .github/workflows/stage0-forensic-audit.yml for repository-wide execution evidence. The resulting artifact is authoritative for that workflow's recorded commit.
