# Canonical Runtime Verification

The repair branch uses `src/ai_cyber_os/hydra.py` as the single runtime implementation surface. The large root-level HYDRA/NEXORA-Cyber source files remain preserved as forensic evidence and are not imported by the runtime.

## Verified gates

The canonical CI gate verifies:

1. Python compilation of the runtime, tooling, and tests.
2. Deterministic forensic inventory.
3. Installation from the declared pyproject.toml dependency contract.
4. Focused pytest verification.
5. All 27 logical HYDRA phases.
6. Phase-8 auxiliary agent checks separately from the 27 logical phases.
7. Final adversarial hardening verification.
8. Forensic baseline artifact presence.

The runtime summary reports `phases=27` and `auxiliary_checks=1`; the auxiliary Phase-8 check is not counted as a 28th logical phase.

## Security boundary

The implementation keeps external/live cyber execution disabled by default. Verification is based on deterministic in-process checks and evidence-aware contracts; passing a test is not treated as evidence of real-world operational execution.

## Legacy policy

Legacy monoliths are retained until semantic equivalence, caller coverage, serialization contracts, and regression evidence justify retirement. They are not runtime dependencies of the canonical package.
