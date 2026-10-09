# Stage 1 — Architecture Reconstruction, Contracts, and Gap Matrix

**Repository:** hasnatahmd21/AI-cyber  
**Audited branch:** repair/forensic-reconstruction  
**Snapshot commit:** fab4a1d15c61488169d99ca922ead2e9cb3c4231  
**Report status:** PROVISIONAL — architecture map recorded; Stage 0 full symbol/call-graph audit remains open  
**Change scope:** documentation only; runtime source and legacy artifacts are not modified.

## 1. Evidence rules

This map is based on the repository tree at the snapshot commit, the canonical package's imports and public entry points, existing architecture/baseline documents, and relevant test contracts. A path existing in the tree proves only that a file exists. A passing unit or deterministic simulation test does not prove a live deployment, external connector, hostile-network containment, or durable self-recovery.

The current session did not rerun the repository's full pytest/CI workflow. Historical verification notes and CI definitions are recorded as repository evidence, not as a new pass claim for this exact snapshot. Any internal details of the very large hydra.py and legacy monoliths not enumerated here remain subject to Stage 0's full AST/symbol/caller audit.

## 2. Canonical runtime selection

The repair branch documents one supported source of truth:

- **src/ai_cyber_os/hydra.py** — 27 logical HYDRA phases and final hardening verification. The file is approximately 2.44 MB in the audited Git tree; it is canonical, but still a monolithic implementation boundary.
- **src/ai_cyber_os/canonical.py** — compatibility re-export of hydra.py; it has no separate phase implementation.
- **src/ai_cyber_os/__main__.py** — python -m ai_cyber_os and the installed ai-cyber entry point.
- **src/ai_cyber_os/intelligence_hydra.py** — an extended dispatcher. It delegates normal phase names to the core runner and adds offline network/malware evaluation aliases and an --extended-all flow.
- **src/ai_cyber_os/ui.py** — localhost HTTP UI/API; its phase executor imports the core hydra.run_hydra_phase directly.
- **pyproject.toml** — package and console-script contract.
- **tests/**, **tools/**, and **.github/workflows/reconstruction.yml** — verification and audit tooling.

The following root-level files are retained as forensic evidence and are explicitly not selected as canonical runtime imports by the repair-branch documentation:

- Assrf next .py
- HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py
- HYDRA_MASTER_RECONSTRUCTED_v2.py
- HYDRA_patched-3.py
- IT_tech__MERGED_ALL_FIXES_APPLIED.py
- New tech .py

Their filenames (including FINAL, RECONSTRUCTED, patched, and MERGED) are not correctness evidence. Keep these files unchanged until Stage 0 establishes symbol provenance, caller coverage, side effects, and semantic equivalence.

## 3. Architecture map from observed call paths

~~~mermaid
flowchart TD
    CLI["CLI: python -m ai_cyber_os / ai-cyber"] --> MAIN["__main__.main"]
    MAIN --> EXT["intelligence_hydra dispatcher"]
    EXT --> CORE["hydra.run_hydra_phase"]
    EXT --> EVAL["Offline network + malware evaluations"]
    CORE --> PHASES["27 logical HYDRA phases"]
    MAIN --> HARD["run_final_hardening_verification"]

    BROWSER["Local browser"] --> HTTP["ui.Handler (127.0.0.1)"]
    HTTP --> APIEXEC["ui._execute"]
    APIEXEC --> CORE
    APIEXEC --> HARD
    HTTP --> GATE["command_gateway.execute"]
    GATE --> APIEXEC
    GATE --> STATUS["Status / regression / local red-team callbacks"]
    HTTP --> KNOWAPI["Knowledge API"]
    KNOWAPI --> PIPE["dataset_pipeline + threat_intel parsers"]
    KNOWAPI --> KNOW["knowledge.py: SQLite + FTS5"]
    KNOW --> RAG["rag.build_context"]
    RAG --> INTEL["runtime_intelligence.analyze"]
    INTEL --> HTTP
    HTTP --> TEL["telemetry: bounded in-memory event buffer"]
    HTTP --> REPORT["operations: atomic latest.json report"]

    MANIFEST["Operator-provided files + manifests"] --> PIPE
    PIPE --> KNOW
    EVAL --> RAGEVAL["security_evaluation / integration_evaluation"]
    RAG --> RAGEVAL
~~~

### Important route difference

The CLI imports the extended dispatcher (intelligence_hydra), while the UI imports run_hydra_phase from core hydra.py. Thus they share the 27-phase core but do not have identical wrapper behavior for the special phase5-intelligence / phase6-malware aliases or --extended-all. Treat this as an explicit contract difference to test—not as proof that either path is wrong.

Phase 8 agent checks are documented and tested as an auxiliary check, not a 28th logical phase.

## 4. Component contracts

| Component | Observed input → output contract | Observed caller / boundary | Evidence anchor |
|---|---|---|---|
| CLI | --phase, --hardening, --extended-all, --json → process exit code and result payload | Installed ai-cyber script and python -m ai_cyber_os | pyproject.toml:1-24; src/ai_cyber_os/__main__.py:19-132 |
| Extended dispatcher | phase name → phase result; special offline evaluation aliases; run_all_extended() combines core run with network/malware evaluations | CLI only in the visible wiring | src/ai_cyber_os/intelligence_hydra.py:13-48 |
| Core HYDRA | phase selector → structured dictionary; aggregate contract exposes 27 logical phases, summary, and a separate Phase-8 auxiliary result | CLI wrapper and UI executor | src/ai_cyber_os/hydra.py; tests/test_canonical_runtime.py |
| Command gateway | string command (1–512 chars) + injected handlers → allowlisted action/result or ValueError | UI /api/command handler | src/ai_cyber_os/command_gateway.py:15-68; tests/test_command_gateway.py |
| UI/API | JSON request → HTTP status + structured response; phase, command, knowledge, status/report/events routes | Local HTTP server bound to 127.0.0.1 | src/ai_cyber_os/ui.py:206-448; tests/test_api_backend_wiring.py |
| Dataset pipeline | manifest and local artifacts → inspection/ingestion result; manifest carries dataset/version/source/license/path/hash/count/schema/status metadata | UI knowledge routes, tools, CLI workflows | src/ai_cyber_os/dataset_pipeline.py:26-295; tests/test_dataset_pipeline.py |
| Knowledge store | normalized records + provenance/hash → SQLite records, relations, FTS and chunk-level FTS retrieval | dataset pipeline, RAG, CLI/UI | src/ai_cyber_os/knowledge.py; docs/KNOWLEDGE_PIPELINE.md |
| RAG / runtime intelligence | query → evidence records, identifiers, relations; answer is null and answer_status is not_generated | UI/API and evaluation consumers | src/ai_cyber_os/rag.py:16-61; src/ai_cyber_os/runtime_intelligence.py:15-31 |
| Security knowledge relationships | source record → family-aware identifier extraction/normalized evidence envelope | knowledge ingestion/correlation | src/ai_cyber_os/security_knowledge.py; src/ai_cyber_os/security_relationships.py |
| Threat-intelligence parsers | operator-downloaded source file + metadata → normalized records; offline parser behavior | dataset/knowledge workflows | src/ai_cyber_os/threat_intel.py; docs/KNOWLEDGE_PIPELINE.md |
| Security evaluation | labelled evaluation cases/outputs → deterministic retrieval, hash, provenance and grounding metrics | tests and evaluation tools | src/ai_cyber_os/security_evaluation.py; evaluation/security_cases.json; tests/test_security_evaluation.py |
| Protected test data | environment-provided AES-GCM key + test secret → encrypted local canary; retrieval fails closed on authorization/decryption errors | controlled adversarial tests | src/ai_cyber_os/protected_data.py:21-71 |
| Telemetry | emitted runtime event → bounded in-process event buffer and current-operation snapshot | UI/API, red-team harness, runtime calls | src/ai_cyber_os/telemetry.py:27-159 |
| Report persistence | result dictionary → atomic replacement of ~/.ai-cyber/reports/latest.json (configurable directory) | UI runtime/regression/red-team handlers | src/ai_cyber_os/operations.py:19-63 |
| Local red-team harness | localhost HTTP rejection cases; CLI-boundary probes; a socket-wrapper egress probe; protected-canary access tests; byte-hash comparison after a controlled file modification | UI's explicit local red-team command and tools/red_blue_adversarial_test.py | src/ai_cyber_os/redteam.py; tools/red_blue_adversarial_test.py; tests/test_security_surface.py |
| Forensic tooling | repository files → AST/symbol/import/duplicate/phase-marker inventory JSON | CI and reconstruction workflow | tools/forensic_inventory.py; tools/forensic_audit.py |

## 5. Gap matrix against the intended architecture

Status meanings: **Observed** means an identifiable code/test contract exists; **Partial** means only a limited part is present; **Not established** means the examined runtime contracts do not prove the requested capability. This is not yet a claim that every possible symbol in the giant monolith has been exhaustively searched.

| Intended capability | Current evidence | Stage 1 status | Proof required before GREEN |
|---|---|---|---|
| One canonical runtime | Core path points to src/ai_cyber_os/hydra.py; root monoliths documented as forensic-only | **Observed, but monolithic** | Stage 0 symbol/caller inventory; preserve public contracts while extracting modules |
| 27 HYDRA logical phases | Aggregate and per-phase tests; Phase 8 auxiliary check is separate | **Observed by repository test contract; rerun needed on snapshot** | Fresh-clone pytest/CI evidence tied to current commit |
| Strong request/security barrier | Strict command grammar, request-size/schema checks, localhost bind, project-root path checks in UI | **Partial** | Authentication/principal model, authorization policy, least privilege, fail-closed tests on every sensitive action |
| Three separate AI layers (analysis → independent validation → approved decision/action) | Core is documented as deterministic in-process runtime; visible package contract has no separate Layer-1/2/3 APIs or model dependency | **Not established** | Explicit typed contracts, independent validator, policy/approval gate, disagreement/low-confidence deny tests; no layer bypass |
| Evidence/RAG/knowledge | Manifest ingestion, SHA-256/count checks, SQLite/FTS5, relationships, evidence-only RAG and evaluation code | **Observed for local deterministic retrieval** | Fresh-store, empty/stale/corrupt-store and genuine source-record E2E tests; preserve provenance through API |
| Cryptographic artifact trust | protected_data.py uses AES-GCM for a local test canary; the red/blue harness compares SHA-256 before/after a local copy is modified | **Partial** | A hash difference alone does not reject a tampered runtime or authenticate a baseline. Add signature verification at trust boundaries, protected key lifecycle/rotation/revocation, a tamper-evident audit chain and negative tests |
| SSRF/outbound-network controls | Legacy Assrf next .py exists; repair docs say root monoliths are not runtime dependencies; red/blue probe monkeypatches socket.create_connection and socket.getaddrinfo during the core run | **Not established as a complete SSRF control** | The monkeypatch probe checks the exercised code path; it is not OS/network-layer egress isolation. Add a dedicated canonical outbound policy, DNS/IP validation, redirect/rebinding coverage, connect-time destination enforcement and network-level isolation tests |
| Deception and attacker containment | redteam.py runs local malformed-request tests; protected_data.py provides a test canary | **Not established as attacker deception/containment** | Isolated decoy service/resources, access-separation controls, event-to-containment trace and proof decoys cannot reach production data |
| Regeneration/recovery | Health/test/report and dataset update components exist; no separate recovery contract is established by this map | **Not established** | Simulated compromise → quarantine → trusted rebuild → secret revocation/rotation → dependency/config validation → rollback decision, with full trace |
| Durable, tamper-evident audit | Telemetry uses a max-500 in-memory deque; report persistence atomically replaces a single latest.json file | **Partial** | Append-only or hash-chained event store, monotonic sequence across restart, restricted write access, tampering detection tests |
| UI/API wiring | API tests exercise handler-to-backend dispatch and reject malformed backend results; UI binds to localhost | **Observed for tested handler paths; browser E2E not established here** | Browser-level checks, unauthorized caller tests, error/denied-action visibility and API→runtime→DB evidence continuity |
| Real external EDR/SIEM/cloud integrations | Baseline explicitly makes no claim of live third-party integrations; connector tests use simulated connector/checkpoint objects | **Not established; simulated contract only** | Real adapter implementation, secret scoping, network policy, contract tests against an explicitly approved sandbox/provider |
| Kaggle/GitHub reproducibility | CI workflow defines compile, inventory, install, pytest, evaluation and pipeline steps | **Workflow defined; current snapshot run not re-executed here** | Fresh clone, pip check, complete tests, HYDRA + hardening, wheel/CLI smoke, logs/artifacts tied to exact SHA |

## 6. Security-boundary decisions

1. **No shell or arbitrary evaluator through the command gateway.** The gateway accepts known commands and injects operation handlers. This is a command-surface restriction, not a substitute for caller authentication or authorization.
2. **Localhost is scope control, not identity.** The UI currently binds to 127.0.0.1; visible route handlers do not establish a user/principal authentication contract. Do not expose this API remotely until the authentication/authorization design is implemented and tested.
3. **AES-GCM canary protection is not full cryptographic trust.** Encryption at rest of one controlled test value does not prove signed build/artifact verification, key rotation/revocation, authenticated internal messaging, or tamper-evident audit.
4. **A red-team event is not containment proof.** Current local scenarios test HTTP input rejection and service survival. They do not demonstrate an attacker has been trapped, isolated, or denied access to production resources.
5. **A successful phase runner is not regeneration proof.** Restarting a process or passing deterministic hardening tests is not equivalent to a compromise-to-trusted-rebuild recovery trace.

## 7. Dependency order for the next stages

- **Stage 0 must continue before implementation refactors:** generate current-commit inventory and exhaustive symbol/line/caller tables for all six root monoliths plus src/ai_cyber_os/hydra.py; trace imports, redefinitions, main guards, I/O, subprocess/network calls, stores, and phase entry points. No legacy merge/delete during this step.
- **Stage 2:** use this map and the completed Stage 0 call graph to define module boundaries/contracts. The 2.44 MB canonical file should not be split by blind text movement.
- **Stages 3–10:** implement security/AI-layer/crypto/SSRF/containment/recovery contracts as separate gated changes with focused negative tests and regression coverage.
- **Stages 11–13:** run adversarial regression, fresh-clone Kaggle/GitHub reproduction, and the end-to-end acceptance scenario only after the required contracts exist.

## 8. Acceptance decision

**Stage 1: DOCUMENTED, NOT GREEN.** The observed runtime and subsystem map is recorded, and major target-vs-current gaps are explicit. Stage 1 is not a certification of the advanced architecture. Its final acceptance depends on Stage 0's deeper source-of-truth analysis and on implementing/testing the unestablished contracts above.

## Stage 0 cross-check and clean-up

The companion [Stage 0 forensic audit protocol](FORENSIC_AUDIT_STAGE_0.md) defines the read-only scan and acceptance gates. The deep JSON/Markdown reports are produced by the reconstruction workflow as a commit-specific artifact. This architecture map must be reviewed against that artifact; static reachability and name collisions are evidence leads, not proof of actual runtime execution. Any mismatch between CLI and UI dispatch, legacy symbols and canonical modules, or claimed security behavior remains a gap until a focused integration test proves it.

## Source anchors

- [Canonical runtime contract](CANONICAL_RUNTIME.md)
- [Reconstruction baseline](RECONSTRUCTION_BASELINE.md)
- [Forensic baseline](FORENSIC_BASELINE.md)
- [Knowledge pipeline](KNOWLEDGE_PIPELINE.md)
- [Canonical HYDRA source](../src/ai_cyber_os/hydra.py)
- [CLI source](../src/ai_cyber_os/__main__.py)
- [UI/API source](../src/ai_cyber_os/ui.py)
- [Command gateway source](../src/ai_cyber_os/command_gateway.py)
- [Protected-data test boundary](../src/ai_cyber_os/protected_data.py)
- [Reconstruction CI workflow](../.github/workflows/reconstruction.yml)
- [Controlled red/blue adversarial harness](../tools/red_blue_adversarial_test.py)
