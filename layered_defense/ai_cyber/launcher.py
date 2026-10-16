"""Run HYDRA (ai_cyber_os) behind the defence pipeline.

Order on every run: integrity check -> barrier -> layer1 -> layer2 -> layer3 -> conditional isolation -> HYDRA supervisor.
HYDRA starts only after the signed integrity baseline and all defence layers allow execution.
Anything other than ALLOW (block, restrict, quarantine, escalate, error) means HYDRA is NOT started."""
from __future__ import annotations

import hashlib
import inspect
import os
import sys
import uuid
from datetime import datetime, timezone
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
    """Load the canonical HYDRA CLI entrypoint from the selected source tree."""
    import importlib
    import importlib.util

    src = os.path.realpath(_repo_src())
    entrypoint = os.path.realpath(os.path.join(src, "ai_cyber_os", "__main__.py"))
    if not os.path.isfile(entrypoint):
        raise ImportError(f"canonical HYDRA CLI entrypoint not found: {entrypoint}")

    # Load the package from its source root when it has not been imported yet,
    # then remove our temporary sys.path addition. Leaving a temporary/custom
    # source root on sys.path leaks test/deployment state into later imports.
    if "ai_cyber_os" not in sys.modules:
        inserted = src not in sys.path
        if inserted:
            sys.path.insert(0, src)
        try:
            importlib.import_module("ai_cyber_os")
        finally:
            if inserted:
                try:
                    sys.path.remove(src)
                except ValueError:
                    pass

    cached = sys.modules.get("ai_cyber_os.__main__")
    cached_path = os.path.realpath(getattr(cached, "__file__", "")) if cached is not None else ""
    if cached is not None and cached_path == entrypoint:
        main = cached.main
    else:
        # A module with the same dotted name may already be cached from a different
        # source tree. Execute this selected file explicitly rather than dispatching
        # into the stale module. Its package context still resolves canonical siblings.
        spec = importlib.util.spec_from_file_location("ai_cyber_os.__main__", entrypoint)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load canonical HYDRA CLI entrypoint: {entrypoint}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        main = module.main

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

        # The extracted brain observes every vetted invocation, but it is not
        # imported until the signed integrity gate above has passed.
        untrusted_input = " ".join(str(arg) for arg in argv)
        event_id = f"runtime-{uuid.uuid4().hex}"
        event = {
            "event_id": event_id,
            "tenant_id": "local",
            "source": "ai_cyber.layered_defence",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "untrusted_input": untrusted_input,
            "payload": {
                "operation": "hydra_cli_invocation",
                "decision": res.decision.value,
                "reason": str(res.reason)[:512],
                "trace": list(res.trace),
                "arguments_count": len(argv),
                "arguments_sha256": hashlib.sha256(untrusted_input.encode("utf-8")).hexdigest(),
            },
        }
        try:
            newtech_result = system.newtech.process_runtime_event(event)
            system.audit.record(
                "newtech_runtime_event",
                event_id=event_id,
                accepted=newtech_result.accepted,
                blocked=newtech_result.blocked,
                fabric_decision=newtech_result.fabric_decision,
                integrity_status=newtech_result.integrity_status,
                trust_state=newtech_result.trust_state,
                loop_id=newtech_result.loop_id or "",
                audit_hash=newtech_result.audit_hash,
            )
            out(
                f"newtech brain: {'BLOCK' if newtech_result.blocked else 'ACCEPT'} "
                f"fabric={newtech_result.fabric_decision} "
                f"integrity={newtech_result.integrity_status} "
                f"trust={newtech_result.trust_state} "
                f"reason={newtech_result.reason}"
            )
            if newtech_result.blocked or not newtech_result.accepted:
                system.audit.record("hydra_not_started", decision="newtech_block")
                return 3
        except Exception as e:
            system.audit.record("newtech_integration_error", error=type(e).__name__)
            system.audit.record("hydra_not_started", decision="newtech_error")
            out(f"newtech brain: BLOCK (integration error: {type(e).__name__})")
            return 3

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
        # Include shutdown in the durable audit record: stop the executor first, then
        # verify and persist the complete chain as authenticated ciphertext.
        try:
            system.shutdown()
        finally:
            out(f"audit chain ok: {system.audit.self_verify()}")
            if audit_file:
                from .adapters.audit_store import save_encrypted
                from .crypto_encryption import AeadCipher
                from .keystore import DefaultKeyProvider
                provider = key_provider or DefaultKeyProvider(os.path.join(os.path.dirname(_repo_src()), ".ai_cyber"))
                save_encrypted(system.audit, audit_file, AeadCipher(provider))
