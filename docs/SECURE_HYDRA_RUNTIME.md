# AI-Cyber Secure HYDRA Runtime

## Execution path

The canonical CLI and UI use the same secured execution path:

1. Load the persistent signing key from `.ai_cyber/` (or `AI_CYBER_KEY_DEFAULT`).
2. Verify the signed SHA-256 baseline for `src/ai_cyber_os/` and the existing `IT_tech__MERGED_ALL_FIXES_APPLIED.py` asset.
3. Refuse startup on untrusted/dirty first-run source, missing or invalid baselines, or detected source drift.
4. Run the request barrier and the three independent defence layers.
   - Layer 1: request validation and initial policy checks.
   - Layer 2: independent pattern checks plus IT-Tech network-state/invariant evaluation.
   - Layer 3: trust/authority checks plus IT-Tech AuthorityEngine authorization for HYDRA.
5. Dispatch to the existing HYDRA phase runner only after an explicit ALLOW.
6. Persist a hash-chained JSONL audit with a signed count/final-hash manifest.

The IT-Tech module is loaded as a module only after its source file passes the signed integrity check. The adapter fails closed on malformed risk/posture data and authority/network-engine errors. The existing IT-Tech source remains in AI-Cyber; Vexon is not modified by this integration.

## First run and key management

A missing baseline deliberately blocks startup; the runtime never automatically trusts an unknown first-run source tree. On a new trusted checkout, review the source/commit, then explicitly provision the signed baseline (the command also runs `phase1` as a smoke test):

```bash
python -m ai_cyber_os --defence-rebaseline --phase phase1 --json
```

The local signing key and baselines are stored under `.ai_cyber/`, which is ignored by Git. Protect that directory with the same operating-system account and filesystem controls used for other security-sensitive local state.

For production deployments, set `AI_CYBER_KEY_DEFAULT` to a securely provisioned hexadecimal key of at least 16 bytes, and protect/backup it separately from the baseline files. A locally generated key is convenient for a single-user development install; it is not a defence against an attacker who already has write access to both the local key and baseline directory.

Do not use `--defence-rebaseline` as a routine repair shortcut. It signs the current tracked source and must only be used after reviewing and committing intended source changes. `--defence-restore` attempts recovery from the committed Git HEAD, and the runtime exits so restored code can be restarted cleanly.

## Run

```bash
python -m pip install -e '.[dev]'
ai-cyber --phase all --hardening --json
ai-cyber hydra-check --run
```

The local UI is bound to localhost and sends HYDRA execution requests through the same CLI gate. Start it with the project's existing `ai-cyber-ui` entry point.

## Verification

Latest verified code CI at `35690416bfccdbf483db45f92ada9d55b595ffa5`: 225 tests passed; Phase 13 security/RAG evaluation, Stage 0 forensic audit, distributable-wheel smoke test, controlled red-team check, 27-phase runtime verification and final hardening all passed. This verifies the repository CI environment; it is not a substitute for deployment-specific key provisioning, host hardening, or a live adversarial assessment.
