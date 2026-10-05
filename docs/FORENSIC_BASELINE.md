# AI-Cyber Forensic Baseline — Handover State

**Repository:** `hasnatahmd21/AI-cyber`  
**Repair branch:** `repair/forensic-reconstruction`  
**Canonical runtime:** `src/ai_cyber_os/hydra.py`  
**Method:** Git object/tree inspection, full-blob source inspection, runtime verification and CI gates.

## 1. Preserved forensic sources

The repository contains several historical multi-megabyte monoliths. They remain preserved as evidence and are not runtime dependencies:

| File | Approx. size | Lines |
|---|---:|---:|
| `Assrf next .py` | 103 KB | 2,445 |
| `HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py` | 2.19 MB | 87,496 |
| `HYDRA_MASTER_RECONSTRUCTED_v2.py` | 1.13 MB | 42,887 |
| `HYDRA_patched-3.py` | 2.44 MB | 92,378 |
| `IT_tech__MERGED_ALL_FIXES_APPLIED.py` | 2.90 MB | 87,019 |
| `New tech .py` | 1.13 MB | 43,175 |

These files contain repeated phase-generated implementations. Their filenames are historical labels, not proof of correctness or runtime ownership.

## 2. Canonical runtime state

The supported runtime is now explicitly wired through the package:

- `src/ai_cyber_os/hydra.py` — canonical implementation.
- `src/ai_cyber_os/canonical.py` — compatibility export surface.
- `src/ai_cyber_os/__main__.py` — operational CLI.
- `pyproject.toml` — install and console-script contract.
- `tests/` — runtime, CLI, forensic and security-surface verification.
- `tools/` — forensic inventory/audit/reconstruction tooling.
- `.github/workflows/reconstruction.yml` — CI verification gate.

## 3. Verified functional gates

The repair branch verifies:

1. Python compilation.
2. Dependency installation and `pip check`.
3. Forensic inventory.
4. Focused regression/security tests.
5. Complete 27 logical HYDRA phases.
6. Phase-8 auxiliary agent verification.
7. Individual public phase dispatch.
8. Installed CLI and JSON CLI execution.
9. Wheel build and fresh-environment smoke execution.
10. Final adversarial hardening verification.
11. Baseline artifact integrity.

The phase runner reports 27 logical phases plus one auxiliary Phase-8 check. Individual phase dispatch is also exercised so a phase cannot appear healthy only because the aggregate runner succeeded.

## 4. Security and operational boundary

The default runtime is deterministic and in-process. The security surface explicitly prevents the canonical default path from opening live network connections, and the package security tests reject dangerous command-execution/eval/exec surfaces.

External/live cyber execution is **not** claimed as recovered functionality. The repository does not claim live customer deployment, real third-party EDR/SIEM/cloud credentials or integrations, restart-durable persistence, unrestricted network execution, or real-world offensive/defensive cyber execution.

## 5. Handover conclusion

The supported client handover surface is installable and executable through `ai-cyber --phase all --hardening` or `python -m ai_cyber_os --phase all --hardening --json`. The canonical runtime, its phase dispatch, packaging surface and verification gates are connected to one source-of-truth implementation.

Any future live integration must be introduced as a separately verified capability. It must not be inferred from deterministic simulation or test success.
