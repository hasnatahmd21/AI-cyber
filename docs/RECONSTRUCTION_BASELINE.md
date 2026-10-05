# AI-Cyber Reconstruction — Current Handover Baseline

## Canonical runtime

The supported runtime is now the package under `src/ai_cyber_os/`.

- Canonical implementation: `src/ai_cyber_os/hydra.py`
- Compatibility surface: `src/ai_cyber_os/canonical.py`
- Public CLI: `src/ai_cyber_os/__main__.py`
- Packaging contract: `pyproject.toml`
- Verification suite: `tests/`
- Forensic tooling: `tools/`
- CI gate: `.github/workflows/reconstruction.yml`

The root-level multi-megabyte HYDRA/NEXORA-Cyber files remain preserved as forensic evidence. They are not runtime dependencies of the canonical package.

## Current verification status

The repair branch has verified the supported deterministic in-process runtime through:

1. Python compilation.
2. Dependency installation and `pip check`.
3. Forensic inventory.
4. Focused regression and security-surface tests.
5. Complete 27 logical HYDRA phase execution.
6. Separate Phase-8 auxiliary agent verification.
7. Individual public phase dispatch.
8. Installed console entrypoint execution.
9. JSON-only machine-readable CLI execution.
10. Distributable wheel build and fresh-environment smoke execution.
11. Final adversarial hardening verification.
12. Baseline artifact checks.

The runtime summary treats Phase 8 agent checks as one auxiliary check, so the logical phase count remains exactly 27.

## Historical forensic findings

The repository originally contained several large, phase-generated monoliths with repeated symbols and overlapping implementations. Those files are intentionally preserved. They are not selected as runtime sources merely because their filenames contain `FINAL`, `RECONSTRUCTED`, `patched`, or `MERGED`.

This preservation rule prevents accidental loss of behavior while keeping one explicit canonical runtime entry point.

## Supported operational boundary

The current handover surface is a deterministic, evidence-aware, in-process cybersecurity intelligence/verification runtime.

The repository does **not** claim that the reconstructed code has:

- live customer deployment,
- real third-party EDR/SIEM/cloud credentials or integrations,
- persistence durability across independent process restarts,
- unrestricted network execution,
- real-world offensive or defensive cyber execution.

Those capabilities must only be enabled from verified implementation evidence and an explicitly approved integration design. They are not represented as working merely because a test passed.

## Handover rule

A client can install the package, execute the canonical CLI, run all 27 phases, inspect structured JSON results, and run final hardening verification. Any future live integration should be added as a separately verified capability rather than silently widening the current runtime boundary.
