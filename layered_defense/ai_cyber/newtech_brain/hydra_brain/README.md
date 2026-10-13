# hydra_brain — "New Tech" phases 4-16, split, fixed and wired

The useful part of `New_tech_.py` (a 43,000-line, 27-phase file that did not
even parse) as independent modules plus one wiring layer.
**Standard library only. Python 3.10+.** Everything is in-memory.

```
hydra_brain/
  core/       phases 4-16   (wired by HydraBrain)
  optional/   phases 17-22  (fixed + tested, NOT wired)
  brain.py    HydraBrain: adapters that connect the engines
  audit.py    hash-chained decision log (tamper-evident)
  bridge.py   adapter for the platform CyberEvent / EventBus
  tests/      integration tests + run_all
  examples/   demo
```

## Install into your repo
Copy the `hydra_brain/` folder to the repo root, then:

```
python -m hydra_brain.tests.run_all      # all phase tests + 26 wiring tests
python -m hydra_brain.examples.demo
```

## Pipeline

| Stage | Engines | What happens |
|---|---|---|
| ingest | P5 → P8 → P4 → P7 → P11 | integrity check; replayed / stale / contradictory data is quarantined or degraded and **never updates state**; trusted data updates state, links causal memory, and is checked against invariants |
| topology | P6 | assets + links → attack path → intervention points |
| recommend | P10 + P11 gate | ranked ISOLATE / RESTRICT / MONITOR candidates; gate invariants can block |
| authorize | P12 | actor needs the permission **and** no unresolved authority drift |
| simulate | your `simulator` (optional) | viability check; skipped if none supplied |
| verify / loop | P14 + P15 | your executor's result is verified independently; failure → `NEEDS_REPLAN` |
| intent | P13 → P11 | intent constraints are compiled into invariants automatically |
| attribution | P9 | only TRUSTED memory is accepted as evidence |

```python
from hydra_brain import HydraBrain
brain = HydraBrain()
brain.ingest(source_id="edr", payload={"fw": "on"})
```

`respond()` never acts by itself: it calls an `executor` **you** pass in.
Without one it stops at `PLANNED` (dry run).

### Plug into the platform (HYDRA / NEXORA)
```python
from hydra_brain import HydraBrain, PlatformBridge
bridge = PlatformBridge(HydraBrain())
bridge.subscribe_to(platform_event_bus)      # uses EventBus.subscribe(type, handler)
```
The bridge is duck-typed (event_id, tenant_id, source, timestamp, payload,
causation_id). It was written against the platform's `CyberEvent` /
`EventBus` signatures but **not run against the real platform** (it needs
pydantic, which was unavailable when this was built). It never raises into
the bus; failures are collected in `bridge.errors`.

## Two kinds of invariants
* **posture** (`gate=False`): evaluated on every accepted telemetry record;
  violations show up in `IngestResult.violated_invariants`.
* **gate** (`gate=True`): checked *before* any response action; a violation
  or unknown state blocks the action. Keep these separate: a "firewall must
  be on" posture rule should not stop you from isolating a host.

## Bugs fixed in the original code
1. P4  `_transitions` was a dict instead of a list (state creation crashed)
2. P6  missing `timedelta` import
3. P9  test used a zero-width time window (never overlapped)
4. P14 result hash built from a list, validated from a tuple (never matched)
5. P14 `ZeroDivisionError` when evidence integrity was not VALID
6. P15 `create_cycle` never set the cycle hash
7. P16 same list/tuple hash mismatch
8. P18 missing approval raised `KeyError` instead of `ValueError`
9. P19 injection regex missed "ignore all previous instructions"
10. File-level: 25 modules concatenated, stray indented `"""` (SyntaxError)

## Not included (on purpose)
Phase 1 (code audit) and 23-27 (benchmarking / hardening / production /
IP validation) mostly validate the codebase itself or duplicate the
platform's own phases.

## Honest limitations
* **P16 is not a real simulator.** Its steps are a seeded random roll
  (80% pass / 15% inconclusive / 5% fail) unrelated to the action, so it is
  *not* used as a gate. `respond(simulator=...)` takes your own callback;
  `brain.experiment_simulator` exposes P16 for pipeline testing only.
* In-memory only; no persistence. `audit.export_jsonl(path)` can dump the log.
* `default_candidates()` uses heuristic numbers (risk reduction, collateral
  from graph connectivity). Pass `candidate_builder=` to use real data.
* P19 prompt-injection detection is a regex heuristic, not a robust defence.
* The engines are logic/verification models; they protect nothing until real
  telemetry flows in through `ingest()` / the bridge.
