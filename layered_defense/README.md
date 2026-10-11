# AI-CYBER

Layered defence system + the legacy HYDRA POST-CORE code split into independent files.

## Structure
```
ai_cyber/
  contracts.py          shared types/decisions (imports nothing from the package)
  barrier.py            outer barrier: validation, rate limit, authn/authz gate
  layer1.py             primary containment (threat detection, RESTRICT = least privilege)
  layer2.py             independent defence (own rules, own policy check, bypass + correlation)
  layer3.py             critical actions: 2nd-party approval, fail-closed
  crypto_integrity.py   HMAC integrity, key providers (no hardcoded keys)
  trust_authority.py    tokens, permissions, revoke/suspend, approvals
  isolation.py          quarantine + release policy
  deception.py          decoys, served only to quarantined principals
  regeneration.py       signed baseline, verified-clean recovery
  audit_telemetry.py    tamper-evident hash-chain audit log, secret redaction
  orchestrator.py       barrier -> isolation -> L1 -> L2 -> L3, timeouts/errors fail closed
  hydra.py              adapter for the legacy phases (integrity, lossless check, run tests)
  runtime.py            canonical startup / wiring / entry-point scan
  __main__.py           python -m ai_cyber <demo|hydra-check [--run]|entry-points>
  legacy/
    IT_tech__MERGED_ALL_FIXES_APPLIED.py   original file, untouched
    hydra_phases/phase_01..42_*.py         the legacy file split by phase
    split_manifest.json                    hashes, order, dedupe + patch record
    symbol_map.json                        legacy symbol -> module -> deps -> callers -> tests -> status
tests/                  one test file per component + end-to-end
docs/                   LEGACY_INVENTORY.md, GATE_REPORT.md, ARCHITECTURE.md
run_gates.py            runs Gate 0..10 in order, stops at first failure
```

## Use
```
python run_gates.py                 # all gates (about 10 s)
python -m ai_cyber demo
python -m ai_cyber hydra-check --run
python -m unittest discover -s tests -t .      # (pytest also works if installed)
```
Production needs a key: `export AI_CYBER_KEY_DEFAULT=$(python -c "import secrets;print(secrets.token_hex(32))")`

## Important notes
- The legacy file has **42** phases, not 27 (Phase 3 appears twice, identical). All are preserved.
- Each split phase file got one added line, `from __future__ import annotations` (the monolith had it once, module-wide; Phase 13 failed without it). `hydra.verify_lossless()` strips it and proves the pieces reassemble to the exact original (sha256).
- The barrier/layers use simple pattern rules and are a framework, not a complete WAF. Passing gates means those tests pass, not that the system is proven secure.
- Authenticated encryption (confidentiality) is not implemented (stdlib has no AEAD); `aead_available()` reports whether the `cryptography` package is present.
