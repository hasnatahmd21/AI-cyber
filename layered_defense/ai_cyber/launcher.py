"""Run HYDRA (ai_cyber_os) behind the defence pipeline.

Order on every run: integrity check -> barrier -> layer1 -> layer2 -> layer3 -> conditional isolation -> HYDRA supervisor.
HYDRA starts only after the signed integrity baseline and all defence layers allow execution.
Anything other than ALLOW (block, restrict, quarantine, escalate, error) means HYDRA is NOT started."""
from __future__ import annotations

import inspect
import os
import sys
import uuid
from typing import Callable, List, Optional, Sequence

from .contracts import Decision, FinalResult, Request
from .crypto_integrity import Integrity
from .runtime import System, build_system

PRINCIPAL = "operator"
RESOURCE_PREFIX = "hydra:"


def _repo_src() -> str:
    # <repo>/layered_defense/ai_cyber/launcher.py  ->  <repo>/src
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(os.path.dirname(here)), "src")


def default_hydra_main() -> Callable[[Sequence[str]], int]:
    """Locate the existing HYDRA CLI (src/ai_cyber_os/__main__.py: main)."""
    src = _repo_src()
    if os.path.isdir(src) and src not in sys.path:
        sys.path.insert(0, src)
    import importlib
    main = importlib.import_module("ai_cyber_os.__main__").main

    def call(argv: Sequence[str]) -> int:
        try:
            takes_args = len(inspect.signature(main).parameters) > 0
            if takes_args:
                rc = main(list(argv))
            else:
                old = sys.argv
                sys.argv = ["ai-cyber", *argv]
                try:
                    rc = main()
                finally:
                    sys.argv = old
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else (0 if e.code in (None, 0) else 1)
        return 0 if rc is None else int(rc)
    return call


def guard(system: System, argv: Sequence[str]) -> FinalResult:
    """Pass a HYDRA run through the full defence pipeline (one Request)."""
    system.trust.grant(PRINCIPAL, "run", RESOURCE_PREFIX)
    req = Request(
        request_id=f"run-{uuid.uuid4().hex[:12]}", principal=PRINCIPAL, action="run",
        resource=RESOURCE_PREFIX + "run", payload=" ".join(argv),
        credentials=system.trust.issue_token(PRINCIPAL), source="internal",
    )
    return system.orchestrator.handle(req)


def default_paths():
    root = os.path.dirname(_repo_src())
    return (os.path.join(_repo_src(), "ai_cyber_os"),
            os.path.join(root, ".ai_cyber", "hydra_baseline.json"))


def default_defence_paths(hydra_baseline_path: Optional[str] = None):
    """The defence implementation gets its own signed inventory and shares the private state dir."""
    root = os.path.dirname(_repo_src())
    state = os.path.dirname(os.path.abspath(hydra_baseline_path)) if hydra_baseline_path else os.path.join(root, ".ai_cyber")
    return os.path.join(root, "layered_defense", "ai_cyber"), os.path.join(state, "defence_baseline.json")


def _integrity(key_provider) -> Integrity:
    from .keystore import DefaultKeyProvider
    return Integrity(key_provider or DefaultKeyProvider(os.path.join(os.path.dirname(_repo_src()), ".ai_cyber")))


def make_baseline(target: Optional[str] = None, baseline_path: Optional[str] = None, key_provider=None,
                  *, defence_dir: Optional[str] = None, defence_baseline_path: Optional[str] = None) -> int:
    """Explicitly baseline both the canonical HYDRA files and the defence code that guards them."""
    from .integrity_gate import write_baseline
    t, b = default_paths()
    d_t, d_b = default_defence_paths(baseline_path or b)
    integrity = _integrity(key_provider)
    hydra_count = write_baseline(target or t, baseline_path or b, integrity)
    write_baseline(defence_dir or d_t, defence_baseline_path or d_b, integrity)
    return hydra_count


def run(argv: Sequence[str], *, hydra_main: Optional[Callable[[Sequence[str]], int]] = None,
        config: Optional[dict] = None, key_provider=None, audit_file: Optional[str] = None,
        out=print, hydra_dir: Optional[str] = None, baseline_path: Optional[str] = None,
        clean_source: Optional[str] = None, defence_dir: Optional[str] = None,
        defence_baseline_path: Optional[str] = None, defence_clean_source: Optional[str] = None) -> int:
    """Exit codes: 0 ok | 1 HYDRA failed | 2 startup/config error | 3 refused by defence | 4 integrity failed."""
    system = build_system(config, key_provider=key_provider)     # raises StartupError if no key
    try:
        from .integrity_gate import check
        d_t, d_b = default_paths()
        df_t, df_b = default_defence_paths(baseline_path or d_b)
        g = check(
            system,
            hydra_dir or d_t,
            baseline_path or d_b,
            _integrity(key_provider),
            clean_source,
            defence_dir=defence_dir or df_t,
            defence_baseline_path=defence_baseline_path or df_b,
            defence_clean_source=defence_clean_source,
        )
        out(f"integrity: {'OK' if g.ok else 'FAILED'} ({g.reason}){' restored=' + str(len(g.restored)) if g.restored else ''}")
        if not g.ok:
            system.audit.record("hydra_not_started", decision="integrity_failed")
            return 4
        res = guard(system, argv)
        out(f"defence: {res.decision.value}  trace={list(res.trace)}  reason={res.reason}")
        if res.decision is not Decision.ALLOW:
            system.audit.record("hydra_not_started", decision=res.decision.value)
            return 3
        try:
            main = hydra_main or default_hydra_main()
            rc = main(list(argv))
        except Exception as e:                                    # HYDRA crash must not hide in silence
            system.audit.record("hydra_crashed", error=type(e).__name__)
            out(f"HYDRA crashed: {type(e).__name__}: {e}")
            return 1
        system.audit.record("hydra_finished", exit_code=rc)
        return rc
    finally:
        out(f"audit chain ok: {system.audit.self_verify()}")
        if audit_file:
            from .adapters.audit_store import save_encrypted
            from .crypto_encryption import AeadCipher
            from .keystore import DefaultKeyProvider
            provider = key_provider or DefaultKeyProvider(os.path.join(os.path.dirname(_repo_src()), ".ai_cyber"))
            save_encrypted(system.audit, audit_file, AeadCipher(provider))
        system.shutdown()
