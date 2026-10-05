# Operational Readiness

## Current verified surface

The canonical package is installed from `pyproject.toml` and exposes the HYDRA runtime through both:

- `python -m ai_cyber_os`
- the installed `ai-cyber` console command

Both delegate to `src/ai_cyber_os/hydra.py`; no second phase implementation is introduced by the CLI.

## Verification contract

The repair branch requires:

1. syntax compilation of runtime, tooling, and tests;
2. deterministic forensic inventory;
3. package installation from the declared dependency contract;
4. focused pytest verification;
5. complete 27-phase runtime execution;
6. final adversarial hardening verification;
7. direct execution of the installed `ai-cyber` command;
8. baseline artifact integrity.

## Operational boundary

The current canonical implementation is a deterministic in-process cybersecurity intelligence and verification runtime. External/live cyber execution remains disabled by default.

Passing the local runtime gates does not by itself prove deployment into a live customer environment, external integrations, persistence durability across process restarts, or real-world offensive/defensive execution.

Those capabilities must be added only from recovered implementation evidence or an explicitly approved architecture; they are not fabricated as part of forensic reconstruction.