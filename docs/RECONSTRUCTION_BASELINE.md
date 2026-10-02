# AI-Cyber Reconstruction — Forensic Baseline

## Observed repository state

The repository currently has six Python source files and a minimal README.
Direct source inspection found multiple multi-megabyte phase-generated
monoliths.

| File | Approx. size | Lines | Classes | Functions |
|---|---:|---:|---:|---:|
| Assrf next .py | 103 KB | — | — | — |
| HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py | 2.19 MB | 87,496 | 1,150 | 2,706 |
| HYDRA_MASTER_RECONSTRUCTED_v2.py | 1.13 MB | 42,887 | 404 | 1,024 |
| HYDRA_patched-3.py | 2.44 MB | 92,378 | 1,160 | 2,987 |
| IT_tech__MERGED_ALL_FIXES_APPLIED.py | 2.90 MB | 87,019 | 1,200 | 5,616 |
| New tech .py | 1.13 MB | 43,175 | 404 | 1,082 |

## Critical evidence

- IT_tech__MERGED_ALL_FIXES_APPLIED.py contains repeated core definitions
  inside one file. Observed repetitions include Clock (43), EvidenceEmitter
  (43), InvariantSeverity (43), ProvenanceRecorder (40), InvariantViolation
  (40), TrustLabel (14), AuditSink (13), FindingKind (12), IdProvider (11),
  Evidence (11), and several transition/trust primitives.
- HYDRA_MASTER_RECONSTRUCTED_v2.py and New tech .py share a substantial
  architecture lineage but are not identical; behavior must be compared.
- HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py and HYDRA_patched-3.py share many
  domain primitives but are not assumed interchangeable.
- Assrf next .py is much smaller and explicitly describes a self-contained
  control-plane architecture. Its coherence is evidence to inspect, not
  proof of canonicality.

## Reconstruction rules

No file is deleted because it is large, old, patched, or duplicated.
No canonical implementation is selected by filename alone. Every
responsibility must be compared by behavior, consumers, state ownership,
side effects, security properties, and verification evidence.

## Next stages

1. Build symbol/dependency inventory.
2. Cluster definitions by responsibility and behavior.
3. Compare state/evidence/security primitives.
4. Establish canonical contracts.
5. Extract core without deleting legacy sources.
6. Extract security and audit.
7. Wire integration/lifecycle.
8. Add regression/end-to-end tests.
9. Re-run duplicate/dead-code analysis.
10. Retire legacy only after verification.

## Decision record

**DECISION:** dedicated repair branch + read-only forensic tooling first.

**REASON:** the repository contains multiple large phase-generated
monoliths and repeated security primitives; blind deletion risks loss.

**SOURCE IMPLEMENTATIONS:** all six Python files in the repository.

**FUNCTIONALITY PRESERVED:** all existing source files remain untouched at
this stage.

**TESTS:** forensic AST tests added; runtime system verification remains
pending and will not be claimed prematurely.
