"""Canonical secured execution path: integrity -> barrier -> isolation -> L1/L2/L3 -> HYDRA -> persistent audit."""
from __future__ import annotations
import datetime, io, json, os, shutil, subprocess, sys, tarfile, tempfile
from contextlib import redirect_stdout
from typing import Optional, Sequence
from .layered_defense.contracts import Decision, Request
from .layered_defense.integrity_gate import check, check_file, write_baseline, write_file_baseline
from .layered_defense.keystore import DefaultKeyProvider
from .layered_defense.crypto_integrity import Integrity
from .layered_defense.runtime import StartupError, build_system
from .layered_defense.audit_store import save

PACKAGE_REL = os.path.join("src", "ai_cyber_os")
IT_TECH_REL = "IT_tech__MERGED_ALL_FIXES_APPLIED.py"


def _stderr(message: str) -> None:
    print(message, file=sys.stderr)


def _root() -> str:
    """Locate the project checkout, including when this package came from a wheel.

    In an installed wheel, __file__ points into site-packages, not the project
    root. Prefer an explicit project root or the current working project tree;
    fall back to the source-layout root for editable installs. Integrity checks
    still verify every protected asset before any HYDRA code is executed.
    """
    candidates = [
        os.environ.get("AI_CYBER_PROJECT_ROOT"),
        os.getcwd(),
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        candidate = os.path.abspath(candidate)
        if (
            os.path.isfile(os.path.join(candidate, "pyproject.toml"))
            and os.path.isdir(os.path.join(candidate, PACKAGE_REL))
            and os.path.isfile(os.path.join(candidate, IT_TECH_REL))
        ):
            return candidate
    # Return the source-layout location so the normal signed-baseline check
    # fails closed with a clear diagnostic if no project checkout is available.
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _git_clean(root: str) -> bool:
    result = subprocess.run(
        ["git", "-C", root, "status", "--porcelain", "--untracked-files=all", "--", PACKAGE_REL, IT_TECH_REL],
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
    archive = subprocess.run(["git", "-C", root, "archive", "HEAD", PACKAGE_REL.replace(os.sep, "/"), IT_TECH_REL],
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
    it_tech_baseline_path = os.path.join(state, "it_tech_baseline.json")
    it_tech_path = os.path.join(root, IT_TECH_REL)
    provider = DefaultKeyProvider(state)
    integrity = Integrity(provider)
    system = None
    clean = None
    audit_path = os.path.join(state, "audit", datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + ".jsonl")
    rc = 2
    try:
        if rebaseline:
            if not _git_clean(root):
                out("defence: rebaseline refused while source assets are dirty; commit intended changes first")
                return 4
            write_baseline(target, baseline_path, integrity)
            write_file_baseline(it_tech_path, it_tech_baseline_path, integrity)
            out("defence: signed AI-Cyber and IT-Tech baselines updated")
        elif not os.path.exists(baseline_path) or not os.path.exists(it_tech_baseline_path):
            # A clean working tree only proves that files match Git; it does not prove
            # that the checked-out revision is trusted. Never bless an unknown first-run
            # source tree automatically. Require an explicit operator rebaseline command.
            out(
                "defence: signed baseline missing; automatic first-run trust is disabled. "
                "Review the checked-out source and run --defence-rebaseline explicitly."
            )
            return 4

        if restore:
            clean = _clean_source(root)
        gate = check(target, baseline_path, integrity, clean)
        out(f"integrity: {'OK' if gate.ok else 'FAILED'} ({gate.reason})")
        if gate.ok and gate.restored:
            out("integrity: AI-Cyber source restored from trusted Git HEAD; restart to load restored code")
            rc = 4
            return rc
        if not gate.ok:
            out("integrity: HYDRA will not start")
            return 4

        clean_root = os.path.dirname(os.path.dirname(clean)) if clean else None
        clean_it_tech = os.path.join(clean_root, IT_TECH_REL) if clean_root else None
        it_gate = check_file(it_tech_path, it_tech_baseline_path, integrity, clean_it_tech)
        out(f"IT-Tech integrity: {'OK' if it_gate.ok else 'FAILED'} ({it_gate.reason})")
        if it_gate.ok and it_gate.restored:
            out("IT-Tech source restored from trusted Git HEAD; restart to load restored code")
            return 4
        if not it_gate.ok:
            out("integrity: IT-Tech defence will not be loaded; HYDRA will not start")
            return 4

        # Import the existing IT-Tech engine only after both signed source gates pass.
        system = build_system(
            config={"it_tech_source": it_tech_path},
            key_provider=provider,
        )
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
            try:
                system.shutdown()
            except Exception as exc:
                out(f"audit shutdown event failed: {type(exc).__name__}")
            out(f"audit chain ok: {system.audit.self_verify()}")
            try:
                save(system.audit, audit_path, integrity=integrity)
            except Exception as exc:
                out(f"audit persistence failed: {type(exc).__name__}")
        if clean:
            shutil.rmtree(os.path.dirname(os.path.dirname(clean)), ignore_errors=True)
