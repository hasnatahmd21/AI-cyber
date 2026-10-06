# AI-CYBER

Canonical AI-Cyber cybersecurity intelligence and operations runtime.

## Runtime

The verified implementation lives at `src/ai_cyber_os/hydra.py` and exposes
the 27-phase HYDRA runtime plus final hardening verification.

A public operational entry point is provided without duplicating runtime logic:

```bash
ai-cyber --phase all --hardening
```

The same interface is available as a Python module:

```bash
python -m ai_cyber_os --phase all --hardening --json
```

Exit status is `0` only when the requested runtime execution succeeds (and,
when requested, final hardening is verified); failures return a non-zero status.

## Verification

The repair branch verifies:

- Python compilation of the canonical runtime and test/tooling surface
- forensic AST inventory
- focused pytest suite
- complete 27-phase runtime execution
- final adversarial hardening verification
- installed CLI operational execution
- baseline artifact integrity

## Architecture boundary

Legacy monoliths at repository root are preserved as forensic evidence and are
not runtime dependencies.

External/live cyber execution remains disabled by default. The current
canonical runtime is a deterministic, evidence-aware in-process execution
surface; no live operational capability is claimed merely from passing tests.

No legacy source is considered canonical solely because of its filename.

## Controlled Red-Team vs Blue-Team test

The repository includes a local-only adversarial runtime harness:

```bash
python tools/red_blue_adversarial_test.py
```

It runs the canonical runtime first, then probes CLI/input boundaries, fail-closed contracts, network-egress isolation, deterministic repeatability, and controlled source-integrity tampering. It does not target external systems or enable live cyber execution. The final output declares **RED TEAM** when a probe escapes the defensive contract and **BLUE TEAM** when every controlled probe is contained. A JSON report is written to `red_blue_test_report.json`.
## Local operational UI

A localhost-only operational control surface is available without duplicating
HYDRA logic:

```bash
ai-cyber-ui
# open http://127.0.0.1:8765
```

It exposes live runtime status, the 27 phase selectors, selected-phase
execution, and full runtime + hardening execution. The UI binds only to
localhost and delegates execution to the canonical HYDRA runtime. It does not
enable external/live cyber execution.
