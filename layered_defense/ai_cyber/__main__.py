"""Canonical entry point:  python -m ai_cyber <command>"""
from __future__ import annotations

import argparse
import json
import sys

from .contracts import Request, Sensitivity
from .runtime import StartupError, build_system, find_entry_points


def _demo() -> int:
    s = build_system({"ephemeral_key": True})
    s.trust.grant("alice", "read", "/docs/"); s.trust.grant("alice", "delete", "/docs/")
    tok = s.trust.issue_token("alice")
    cases = [
        ("normal read", Request("r1", "alice", "read", "/docs/a.txt", "hello", tok)),
        ("sql injection", Request("r2", "alice", "read", "/docs/a.txt", "x' OR 1=1 --", tok)),
        ("forged token", Request("r3", "alice", "read", "/docs/a.txt", "hi", "alice.deadbeef")),
        ("critical delete w/o approval", Request("r4", "alice", "delete", "/docs/a.txt", None, tok, sensitivity=Sensitivity.CRITICAL)),
    ]
    ok = True
    for name, req in cases:
        res = s.orchestrator.handle(req)
        print(f"{name:32s} -> {res.decision.value:10s} {res.trace}")
    print("audit chain ok:", s.audit.self_verify())
    s.shutdown()
    return 0 if ok else 1


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["secure"]:        # project entry: defence + HYDRA together (same as the `ai-cyber` command)
        from .secured import main as secured_main
        return secured_main(argv[1:])
    ap = argparse.ArgumentParser(prog="ai_cyber")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo")
    h = sub.add_parser("hydra-check"); h.add_argument("--run", action="store_true", help="also run all phase tests")
    sub.add_parser("entry-points")
    r = sub.add_parser("run", help="run HYDRA behind the always-on defence: python -m ai_cyber run -- <hydra args>")
    r.add_argument("hydra_args", nargs=argparse.REMAINDER)
    sub.add_parser("baseline", help="explicitly create/update the signed HYDRA code baseline")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "demo":
            return _demo()
        if a.cmd == "run":
            from .secured import main as secured_main
            args = a.hydra_args[1:] if a.hydra_args[:1] == ["--"] else a.hydra_args
            return secured_main(args)
        if a.cmd == "baseline":
            from .launcher import make_baseline
            print("baseline files:", make_baseline())
            return 0
        if a.cmd == "entry-points":
            import os
            for p in find_entry_points(os.path.dirname(os.path.abspath(__file__))):
                print(p)
            return 0
        if a.cmd == "hydra-check":
            from .hydra import Hydra
            hy = Hydra()
            bad = hy.verify_files(); ll = hy.verify_lossless()
            print(f"phases: {len(hy.phase_numbers())}  files_intact: {not bad}  lossless_vs_original: {ll}")
            ok = not bad and ll
            if a.run:
                # Running all HYDRA phases is an execution path, not a passive file check.
                from . import secured
                secured.enforce(["hydra-check", "--run"])
                try:
                    res = hy.run_all()
                    for r in res:
                        print(f"phase {r.phase:02d}: {r.passed} passed, {r.failed} failed {'OK' if r.ok else 'FAIL '+r.detail}")
                    print("total passed:", sum(r.passed for r in res))
                    ok = ok and all(r.ok for r in res)
                finally:
                    secured.ACTIVE = False
            return 0 if ok else 1
    except StartupError as e:
        print(f"startup error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
