# AI-Cyber secured HYDRA runtime

This branch routes HYDRA execution through one canonical defence path. It keeps the existing HYDRA phase dispatcher and adds the layered-defence gate around it.

## Execution order

1. Verify the signed source baseline for `src/ai_cyber_os/` and `IT_tech__MERGED_ALL_FIXES_APPLIED.py`.
2. Initialize the local signing key if neither a valid environment key nor a local key exists.
3. Run the request through the perimeter barrier, isolation checks, Layer 1, Layer 2 and Layer 3.
4. Layer 2 evaluates the IT-Tech network-state engine; Layer 3 evaluates the IT-Tech authority engine. Invalid or high-risk telemetry is denied.
5. Start the existing HYDRA phase runner only when the defence decision is `ALLOW`.
6. Persist the hash-chained audit log and a manifest containing the record count and final hash. The manifest is HMAC-signed when the runtime key is available.

Any non-`ALLOW` decision prevents HYDRA execution. Defence and integrity failures fail closed.

## Commands

Install from the repository root:

```bash
python -m pip install -e .
```

Run all HYDRA phases and final hardening through the secured entry point:

```bash
python -m ai_cyber_os --phase all --hardening --json
```

Run the explicit HYDRA integrity check and, if requested, the full phase runner:

```bash
python -m ai_cyber_os hydra-check --run
```

Start the local operational UI with `ai-cyber-ui`. UI execution requests are delegated through the same secured CLI path; the UI is not an alternate bypass.

## Resident defence while the project is running

The UI now starts a resident `DefenceSupervisor` **before** it opens the control surface. Startup fails closed if either signed source baseline is missing/invalid, the IT-Tech network engine is unavailable, the AuthorityEngine denies its startup check, or the audit chain is unhealthy. Every UI-initiated HYDRA run must first receive `ALLOW` from this resident, stateful pipeline and then pass the normal secured CLI integrity and layered-defence checks. The resident monitor rechecks signed source integrity, IT-Tech network state, authority decisions, and audit-chain health at the configured interval. On a monitor failure it latches itself blocked for the lifetime of that process; operators must investigate rather than resume execution in-place.

The live monitor state is available from the UI at:

```text
GET /api/defence
```

The response includes `active`, `ready`, `status`, `last_check_at`, and per-gate check results. A `not_started` or `blocked` state is not healthy.

For a headless host where the UI is not running, start the long-lived guard service after baseline initialization:

```bash
ai-cyber-guard --root /path/to/AI-cyber --interval 2
```

Use either the UI's resident monitor or the standalone guard as the resident manager for a working tree; one-shot CLI operations continue to enforce their own integrity and layered gates either way. For a durable deployment, supervise `ai-cyber-guard` with the host's service manager so it starts after reboot and restarts after unexpected process exit.

Example systemd unit (replace paths and service account for the deployment):

```ini
[Unit]
Description=AI-Cyber resident defence monitor
After=network.target

[Service]
Type=simple
User=ai-cyber
WorkingDirectory=/opt/AI-cyber
ExecStart=/opt/AI-cyber/.venv/bin/ai-cyber-guard --root /opt/AI-cyber --interval 2
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/AI-cyber/.ai_cyber

[Install]
WantedBy=multi-user.target
```

This is a deployment template, not a claim that a systemd/Codespaces host has been provisioned. The monitor is active only while the UI or guard process is running; host-level persistence requires installing and validating the appropriate service-manager configuration. The current network-state engine evaluates security telemetry delivered to the runtime; it should not be mistaken for a packet-capture sensor or a substitute for OS-level EDR/firewall telemetry until those event sources are explicitly integrated.

## Local key and state

- Runtime state is stored in `.ai_cyber/`, which is ignored by Git.
- The default local key is `.ai_cyber/key`; the key provider creates it with restrictive file permissions. Keep the entire state directory private and backed up according to your operational policy.
- An environment key can be supplied as `AI_CYBER_KEY_DEFAULT` using hex-encoded key material (at least 16 bytes). Changing key material invalidates existing signed baselines and audit-manifest signatures.
- Signed source baselines and persistent audit records live under `.ai_cyber/`. Audit JSONL files have matching `.manifest.json` files; a missing or mismatched manifest is treated as an integrity failure by `load_verified`.

### First-run trust is explicit

A missing signed baseline is **not** created automatically, even when the Git working tree is clean. A clean tree proves only that files match the checked-out commit; it does not establish that the commit itself is trusted. Review the branch, commit, and protected source files first, then explicitly initialize the baseline:

```bash
python -m ai_cyber_os --defence-rebaseline --phase all --json
```

This command refuses to sign the source if the protected package or IT-Tech monolith has uncommitted or untracked changes. Treat rebaselining as a trust decision and perform it only on a reviewed revision.

## Intentional source updates and recovery

After intentionally changing source code, commit the intended changes first, then run:

```bash
python -m ai_cyber_os --defence-rebaseline --phase all --json
```

Rebaselining is refused when the protected source paths contain uncommitted or untracked changes.

To restore a previously signed baseline from the current trusted Git `HEAD`:

```bash
python -m ai_cyber_os --defence-restore --phase all --json
```

Recovery proceeds only when the Git source matches the signed baseline. After a restoration, the command exits without loading the changed code; restart the command to run the restored version.

## Verification status

GitHub Actions passed on commit `7f3372820e1a2836a087de797a590c260a1e5fa8`:

- Python compile step: PASS
- Full test suite: **221 passed in 52.24 seconds**
- Phase 13 standalone security/RAG evaluation: PASS
- Phase 13 tamper detection and end-to-end evaluation: PASS
- Retrieval/evidence metrics reported by the evaluator: precision@k, recall@k, MRR, nDCG@k, evidence quality, and output grounding all `1.0`

This verifies the repository's automated CI environment. It does not prove that a particular Codespaces workspace has been smoke-tested with its own provisioned key, persisted baseline, and recovery workflow.
