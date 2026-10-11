"""Canonical secured execution path: integrity -> barrier -> isolation -> L1/L2/L3 -> HYDRA -> persistent audit."""
from __future__ import annotations
import datetime, io, json, os, shutil, subprocess, sys, tarfile, tempfile
from contextlib import redirect_stdout
from typing import Optional, Sequence
from .layered_defense.contracts import Decision, Request
from .layered_defense.integrity_gate import check, write_baseline
from .layered_defense.keystore import DefaultKeyProvider
from .layered_defense.crypto_integrity import Integrity
from .layered_defense.runtime import StartupError, build_system
from .layered_defense.audit_store import save

PACKAGE_REL = os.path.join("src", "ai_cyber_os")


def _stderr(message: str) -> None:
    print(message, file=sys.stderr)


def _root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _git_clean(root: str) -> bool:
    result = subprocess.run(
        ["git", "-C", root, "status", "--porcelain", "--untracked-files=all", "--", PACKAGE_REL],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return False
    # Python imports/compileall create disposable cache files; they are not source drift.
    for line in result.stdout.splitlines():
        path = line[3:].strip().replace("\\", "/")
        if "/__pycache__/" in f"/{path}/" or path.endswith((".pyc", ".pyo")):
            continue
        return False
    return True


def _clean_source(root: str) -> str:
    archive = subprocess.run(["git", "-C", root, "archive", "HEAD", PACKAGE_REL.replace(os.sep, "/")],
                             check=True, capture_output=True).stdout
    temp = tempfile.mkdtemp(prefix="ai_cyber_trusted_")
    with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
        stream.extractall(temp, filter="data")
    return os.path.join(temp, PACKAGE_REL)


def _success(result) -> bool:
    if not isinstance(result, dict): return False
    if result.get("success") is False or result.get("verified") is False: return False
    if result.get("status") in {"FAIL", "FAILED", "EXCEPTION", "ERROR"}: return False
    if result.get("failed", 0) or result.get("tests_failed", 0) or result.get("failures"): return False
    summary = result.get("summary")
    if isinstance(summary, dict): return _success(summary)
    return True


def _hydra(argv: Sequence[str]) -> int:
    """Execute the existing HYDRA dispatcher directly, without re-entering this CLI."""
    from .hydra import run_final_hardening_verification
    from .intelligence_hydra import run_hydra_phase, run_all_extended
    import argparse
    parser = argparse.ArgumentParser(prog="ai-cyber")
    parser.add_argument("--phase", default="all")
    parser.add_argument("--hardening", action="store_true")
    parser.add_argument("--extended-all", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv))
    captured = io.StringIO()
    with redirect_stdout(captured):
        phase_result = run_all_extended() if args.extended_all else run_hydra_phase(args.phase)
        payload = {"phase_result": phase_result}
        if args.hardening: payload["hardening_result"] = run_final_hardening_verification()
    success = _success(phase_result)
    if args.extended_all:
        success = bool(phase_result.get("summary", {}).get("success", False))
    if args.hardening:
        success = success and bool(payload["hardening_result"].get("verified", False))
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        if captured.getvalue(): print(captured.getvalue(), file=sys.stderr, end="")
    else:
        summary = phase_result.get("summary", {}) if isinstance(phase_result, dict) else {}
        print(f"AI-Cyber runtime: success={success} phases={summary.get('phases', 'n/a')} auxiliary_checks={summary.get('auxiliary_checks', 'n/a')}")
        if args.hardening:
            print(f"Final hardening: verified={payload['hardening_result'].get('verified', False)} failed={payload['hardening_result'].get('failed', 'n/a')}")
    return 0 if success else 1


def main(argv: Optional[Sequence[str]] = None, *, root: Optional[str] = None, out=print) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    rebaseline = "--defence-rebaseline" in argv
    restore = "--defence-restore" in argv
    args = [a for a in argv if a not in ("--defence-rebaseline", "--defence-restore")]
    if "--json" in args and out is print:
        out = _stderr
    root = root or _root()
    target = os.path.join(root, PACKAGE_REL)
    state = os.path.join(root, ".ai_cyber")
    baseline_path = os.path.join(state, "hydra_baseline.json")
    provider = DefaultKeyProvider(state)
    integrity = Integrity(provider)
    system = None
    clean = None
    audit_path = os.path.join(state, "audit", datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + ".jsonl")
    rc = 2
    try:
        if rebaseline:
            if not _git_clean(root):
                out("defence: rebaseline refused while source tree is dirty; commit intended changes first")
                return 4
            write_baseline(target, baseline_path, integrity)
            out("defence: signed baseline updated")
        elif not os.path.exists(baseline_path):
            if not _git_clean(root):
                out("defence: first baseline refused because src/ai_cyber_os has uncommitted or untracked files")
                return 4
            count = write_baseline(target, baseline_path, integrity)
            out(f"defence: trusted baseline initialized ({count} files)")
        if restore:
            clean = _clean_source(root)
        system = build_system(key_provider=provider)
        gate = check(target, baseline_path, integrity, clean)
        out(f"integrity: {'OK' if gate.ok else 'FAILED'} ({gate.reason})")
        if gate.ok and gate.restored:
            system.audit.record("source_restored", files=gate.restored)
            out("integrity: source restored from trusted Git HEAD; restart the command to load the restored code")
            rc = 4
            return rc
        if not gate.ok:
            system.audit.record("hydra_not_started", decision="integrity_failed", reason=gate.reason)
            rc = 4
            return rc
        system.trust.grant("hydra-runtime", "read", "hydra:")
        token = system.trust.issue_token("hydra-runtime")
        request = Request(request_id="hydra-startup", principal="hydra-runtime", action="read",
                          resource="hydra:run", payload=" ".join(args), credentials=token, source="internal")
        result = system.orchestrator.handle(request)
        out(f"defence: {result.decision.value} trace={list(result.trace)} reason={result.reason}")
        if result.decision is not Decision.ALLOW:
            system.audit.record("hydra_not_started", decision=result.decision.value)
            rc = 3
            return rc
        if args[:1] == ["hydra-check"]:
            from .hydra import Hydra
            verifier = Hydra()
            problems = verifier.verify_files()
            lossless = verifier.verify_lossless()
            print(f"HYDRA integrity: files_intact={not problems} lossless_vs_original={lossless}")
            rc = 0 if not problems and lossless else 1
            if rc == 0 and "--run" in args:
                from .intelligence_hydra import run_hydra_phase
                result = run_hydra_phase("all")
                print(json.dumps(result, indent=2, sort_keys=True, default=str))
                rc = 0 if _success(result) else 1
        else:
            rc = _hydra(args)
        system.audit.record("hydra_finished", exit_code=rc)
        return rc
    except StartupError as exc:
        out(f"defence startup error: {exc}")
        return 2
    except Exception as exc:
        out(f"secure runtime failed closed: {type(exc).__name__}: {exc}")
        if system: system.audit.record("secure_runtime_error", error=type(exc).__name__)
        return 4
    finally:
        if system:
            out(f"audit chain ok: {system.audit.self_verify()}")
            try: save(system.audit, audit_path)
            except Exception as exc: out(f"audit persistence failed: {type(exc).__name__}")
            system.shutdown()
        if clean:
            shutil.rmtree(os.path.dirname(os.path.dirname(clean)), ignore_errors=True)
