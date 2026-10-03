# AI-CYBER

Canonical AI-Cyber cybersecurity intelligence and operations runtime.

## Runtime

The verified implementation lives at `src/ai_cyber_os/hydra.py` and exposes
the 27-phase HYDRA runtime plus final hardening verification.

Legacy monoliths at repository root are preserved as forensic evidence and are
not runtime dependencies.

## Verification

The repair branch verifies:

- Python compilation of the canonical runtime and test/tooling surface
- forensic AST inventory
- focused pytest suite
- complete 27-phase runtime execution
- final adversarial hardening verification
- baseline artifact integrity

No legacy source is considered canonical solely because of its filename.
