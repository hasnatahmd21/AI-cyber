# AI-CYBER Hardening + Regression Layer

Stage #10 is the fail-closed regression boundary for the canonical runtime.

The gate verifies the complete #1–#9 path rather than treating each stage as an isolated feature. It covers HTTP/API contracts, request-id safety, bounded query inputs, telemetry integrity, exact time-window semantics, command failure containment, execution/output limits, backend integrity propagation, end-to-end evidence/telemetry/command connectivity, UI security contracts, full-suite regression, Python 3.11/3.12/3.13 compatibility, and deterministic regression under two hash seeds.

## Failure policy

A single failed test, compilation error, dependency-consistency error, canonical runtime failure, or deterministic-regression failure blocks the GREEN gate. No stage is considered hardening-complete from a partial test pass.

## Runtime boundary

The hardening layer does not add an LLM provider, autonomous remediation, unrestricted execution, or external runtime asset dependency. It strengthens the existing evidence-first, local-first architecture.

## CI entry point

GitHub Actions workflow:

`.github/workflows/hardening-regression.yml`

Primary local command:

`python -m pytest -q`

Focused adversarial gate:

`python -m pytest -q tests/test_hardening_regression.py tests/test_security_surface.py`
