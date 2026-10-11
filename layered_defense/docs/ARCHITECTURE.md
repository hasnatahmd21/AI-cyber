# Architecture

Request flow (`orchestrator.py`): integrity check -> barrier (authentication/token verification included) -> Layer 1 -> Layer 2 -> Layer 3 -> conditional isolation/decoy handling -> decision -> audit.

Startup integrity gate (outside the per-request pipeline):

- Verify the HMAC-signed HYDRA source inventory and the separate signed inventory for the defence implementation before processing a run.
- Inventory comparison includes changed, missing and unexpected files. Unsafe filesystem entries are rejected rather than followed.
- Explicit recovery uses only a Git-HEAD tree whose bytes match its signed baseline. It restores the disk tree and fails the current invocation; a fresh process must reload and reverify the code before HYDRA can execute.
- Baseline updates are operator-controlled. First-start initialization is permitted only without prior audit history; missing baselines after audit activity require explicit rebaseline review.


* Authentication/authorization is enforced at the barrier AND re-checked independently by Layer 2 and Layer 3
  (no layer trusts an earlier "pass").
* Unknown/invalid input, layer exceptions, timeouts and wrong result types all produce `Decision.ERROR`, which is not authorized.
* Only `ALLOW` and `RESTRICT` are authorized (`contracts.is_authorized`).
* Layer 2 quarantines a principal after repeated suspicious requests; quarantined principals only ever reach decoys.
* There is no test-mode switch: tests use the same `build_system` with an injected key provider.
* Keys come from `KeyProvider` (env `AI_CYBER_KEY_<ID>` or injected); nothing is hardcoded.
