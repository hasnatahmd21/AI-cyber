# AI-Cyber Client Handover

## Install

```bash
python -m venv .venv
# Linux/macOS/Colab:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .
python -m pip check
```

## Run the complete supported runtime

```bash
ai-cyber --phase all --hardening
```

Machine-readable output:

```bash
ai-cyber --phase all --hardening --json
```

Python-module entrypoint:

```bash
python -m ai_cyber_os --phase all --hardening --json
```

## Run one phase

```bash
ai-cyber --phase phase1
ai-cyber --phase phase27
```

Every public phase (`phase1` through `phase27`) is independently dispatchable and is checked for a real result rather than an implicit `None` success.

## What the handover verifies

- 27 logical HYDRA phases.
- One separate Phase-8 auxiliary agent verification surface.
- Runtime, CLI and wheel execution.
- Dependency consistency.
- Security-surface regression checks.
- Final adversarial hardening.
- Structured JSON results for automation.

## Boundary

This handover covers the verified deterministic in-process runtime. It does not claim live customer deployment, real third-party EDR/SIEM/cloud integrations, restart-durable persistence, unrestricted network execution, or real-world offensive/defensive cyber execution.

Those are separate capabilities and must be implemented and verified separately rather than represented by simulated or test-only behavior.

## Client acceptance

A clean client acceptance run is complete when:

1. `python -m pip check` succeeds.
2. `pytest -q` succeeds.
3. `ai-cyber --phase all --hardening --json` exits with code 0.
4. JSON reports `phase_result.summary.success=true`.
5. JSON reports `hardening_result.verified=true` and `hardening_result.failed=0`.
