# Architecture

Request flow (`orchestrator.py`): Barrier -> isolation/decoy gate -> Layer 1 -> Layer 2 -> Layer 3 -> decision -> audit.

* Authentication/authorization is enforced at the barrier AND re-checked independently by Layer 2 and Layer 3
  (no layer trusts an earlier "pass").
* Unknown/invalid input, layer exceptions, timeouts and wrong result types all produce `Decision.ERROR`, which is not authorized.
* Only `ALLOW` and `RESTRICT` are authorized (`contracts.is_authorized`).
* Layer 2 quarantines a principal after repeated suspicious requests; quarantined principals only ever reach decoys.
* There is no test-mode switch: tests use the same `build_system` with an injected key provider.
* Keys come from `KeyProvider` (env `AI_CYBER_KEY_<ID>` or injected); nothing is hardcoded.
