# AI-Cyber Forensic Baseline

> **Historical snapshot notice (Stage 0 follow-up, 2026-10-09):** Quantities and findings in this document describe baseline commit `fd3dceef411191be84ff4f38d05ea9835776aaf5` only; they are not a current inventory of `main`. At the start of this Stage 0 work, `main` pointed to `fed337131518e7fedebdac6314dff7d61fc7e68f` and already contained `src/ai_cyber_os/`, tests, tooling, and `pyproject.toml`. Use the commit-specific artifact from `.github/workflows/stage0-forensic-audit.yml` for the refreshed inventory. Historical findings below remain useful leads but require current-revision revalidation.

**Repository:** `hasnatahmd21/AI-cyber`  
**Baseline commit:** `fd3dceef411191be84ff4f38d05ea9835776aaf5`  
**Repair branch:** `repair/forensic-reconstruction`  
**Method:** Git object/tree inspection + full-blob AST-level symbol inventory where source blobs were readable.

## 1. Baseline inventory

At the historical baseline commit above, the inspected tree contained six Python sources plus a minimal README:

| Source | Approx. size | Lines | Classes | Functions |
|---|---:|---:|---:|---:|
| Assrf next .py | 103 KB | 2,445 | 106 | 139 |
| HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py | 2.19 MB | 87,496 | 1,150 | 2,706 |
| HYDRA_MASTER_RECONSTRUCTED_v2.py | 1.13 MB | 42,887 | 404 | 1,024 |
| HYDRA_patched-3.py | 2.44 MB | 92,378 | 1,160 | 2,987 |
| IT_tech__MERGED_ALL_FIXES_APPLIED.py | 2.90 MB | 87,019 | 1,200 | 5,616 |
| New tech .py | 1.13 MB | 43,175 | 404 | 1,082 |

Aggregate observed source volume is approximately **10.0 MB / 355,400 lines / 4,424 classes / 13,554 function definitions**.

## 2. Immediate forensic findings

### A. The repository is dominated by generated/merged monoliths

Five files are between roughly 1.1 MB and 2.9 MB and contain hundreds to thousands of definitions. They are not suitable as the final modular architecture.

### B. Duplicate implementation pressure is confirmed

The AST inventory found repeated class/function names inside the large files. Examples include:

- `TestHealthConnector`
- `Clock`
- `IdProvider`
- `EvidenceEmitter`
- `ProvenanceRecorder`
- `AuditSink`
- `Evidence`
- `AuthorityEngine`
- `to_dict`
- `__init__`
- `__post_init__`
- `validate`
- `get_state`
- `add_evidence`
- `record_action`
- `record_verification`

These names are **not being treated as automatically equivalent**. Each implementation must be compared by behavior, state, callers, contracts and side effects before canonicalization.

### C. Phase-generated composition is visible

The large sources contain repeated phase markers:

- HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py: ~398 phase markers
- HYDRA_MASTER_RECONSTRUCTED_v2.py: ~188
- HYDRA_patched-3.py: ~430
- IT_tech__MERGED_ALL_FIXES_APPLIED.py: ~55
- New tech .py: ~188

This is evidence of repeated phase integration/merge history, not evidence that the newest phase copy is authoritative.

### D. The historical baseline had no meaningful package structure

At that historical revision, the main branch had no established `src/` package, test suite, configuration package, or documented public API. README was only 10 bytes. Those statements do not describe the newer main revision; use the fresh Stage 0 artifact for current state.

### E. Several large files cannot be safely selected as canonical from filename alone

The filenames explicitly contain terms such as `FINAL`, `RECONSTRUCTED`, `patched`, and `MERGED`. Those labels are historical metadata only. They are not accepted as proof of correctness.

### F. Existing reconstruction automation is not yet trusted

The repair branch inherited a prior `tools/reconstruct.py` and workflow. Static inspection found architectural defects in that automation, including:

1. It hard-codes `HYDRA_patched-3.py` as the reconstruction source.
2. It generates files under `src/ai_cyber_os` while also creating a compatibility file that imports `ai_cyber_os.reconstructed`, a path not created by the shown generator.
3. It assumes first top-level symbol definition is canonical when duplicate definitions exist.
4. It emits generated modules without first proving behavioral equivalence.
5. Its workflow automatically commits generated output before the required integration/regression/end-to-end verification gates.

**Conclusion:** the existing generator is treated as experimental tooling, not as an authoritative reconstruction mechanism.

## 3. Canonicalization status

No major responsibility has been declared canonical yet.

That is intentional.

The next stage must establish capability and responsibility maps before deleting or merging implementations.

Required canonical domains include, where supported by actual source evidence:

- identifiers/types
- state and state transitions
- evidence/provenance
- audit/integrity
- security/policy
- trust/authority
- containment
- telemetry
- lifecycle/orchestration
- persistence
- configuration
- integration/health
- error hierarchy
- compatibility surface

## 4. Preservation rule

All six original source files remain preserved as legacy evidence.

No large source is deleted merely because it is duplicated.

No implementation is declared obsolete until callers, registrations, dynamic references, serialization contracts, tests and runtime entry points have been checked.

## 5. Reconstruction sequence

1. Build complete AST symbol inventory.
2. Build definition-to-reference and import dependency maps.
3. Extract capability inventory from executable code and tests.
4. Group duplicate candidates by responsibility rather than name.
5. Select/merge canonical implementations with evidence.
6. Establish a clean package dependency direction.
7. Extract small responsibility modules.
8. Add explicit integration wiring.
9. Build unit, integration, regression and end-to-end verification.
10. Retire legacy implementations only after the new path is proven.
11. Re-run duplicate/dead-code/circular-dependency gates.
12. Review the final architecture and capability inventory.

## 6. Current verification statement

**Not repaired yet.**

The repository has been forensically characterized enough to identify the main reconstruction risks, but no claim of functional completion is being made.

The repair gate remains open until actual compilation, imports, unit tests, integration tests, regression tests and end-to-end execution provide evidence.
