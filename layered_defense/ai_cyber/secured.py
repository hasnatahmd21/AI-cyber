"""The project's real entry: defence + HYDRA as one system.   ai-cyber [--defence-*] <hydra args>

  --defence-rebaseline   explicitly accept current HYDRA + defence files as trusted
  --defence-restore      restore drifted files from git HEAD (verified against signed baselines)
Recovery blocks this process after writing files; rerun without --defence-restore to load repaired code.
Key, signed baselines and audit logs are managed in <repo>/.ai_cyber/."""
from __future__ import annotations

import datetime
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Callable, Optional, Sequence

from .crypto_integrity import Integrity
from .integrity_gate import write_baseline
from .keystore import DefaultKeyProvider
from . import launcher

HYDRA_REL = os.path.join("src", "ai_cyber_os")
DEFENCE_REL = os.path.join("layered_defense", "ai_cyber")

ACTIVE = False   # True only while this process is already vetted by the defence (in-process flag, not an env switch)


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def git_clean_source(root: str, rel: str = HYDRA_REL) -> str:
    """Pristine copy of the HYDRA dir from git HEAD, in a temp dir (caller deletes it)."""
    data = subprocess.run(["git", "-C", root, "archive", "HEAD", rel.replace(os.sep, "/")],
                          check=True, capture_output=True).stdout
    tmp = tempfile.mkdtemp(prefix="aicyber_clean_")
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(tmp, filter="data")
    return os.path.join(tmp, rel)


def _audit_history_exists(audit_dir: str) -> bool:
    """Any prior audit entry, even damaged or unreadable, prevents implicit re-baselining."""
    try:
        with os.scandir(audit_dir) as entries:
            return next(entries, None) is not None
    except FileNotFoundError:
        return False
    except OSError:
        return True


def main(argv: Optional[Sequence[str]] = None, *, root: Optional[str] = None,
         hydra_main: Optional[Callable[[Sequence[str]], int]] = None, out=print) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    rebaseline = "--defence-rebaseline" in argv
    restore = "--defence-restore" in argv
    args = [a for a in argv if a not in ("--defence-rebaseline", "--defence-restore")]

    def vetted(a):                      # HYDRA starts only after ALLOW; its own entry hook then sees ACTIVE
        global ACTIVE
        ACTIVE = True
        try:
            return (hydra_main or launcher.default_hydra_main())(a)
        finally:
            ACTIVE = False

    root = root or repo_root()
    state = os.path.join(root, ".ai_cyber")
    target = os.path.join(root, HYDRA_REL)
    baseline = os.path.join(state, "hydra_baseline.json")
    defence_target = os.path.join(repo_root(), DEFENCE_REL)
    defence_baseline = os.path.join(state, "defence_baseline.json")
    audit_dir = os.path.join(state, "audit")

    if restore and rebaseline:
        out("defence: BLOCK (restore and rebaseline are mutually exclusive)")
        return 4

    missing_baselines = [p for p in (baseline, defence_baseline) if not os.path.exists(p)]
    if missing_baselines and restore and not rebaseline:
        out("defence: BLOCK (restore requires both signed baselines; explicit rebaseline required)")
        return 4
    if missing_baselines and not rebaseline and _audit_history_exists(audit_dir):
        out("defence: BLOCK (a signed baseline is missing while prior audit history exists; explicit rebaseline required)")
        return 4

    provider = DefaultKeyProvider(state)
    integrity = Integrity(provider)
    if rebaseline or missing_baselines:
        n_hydra = write_baseline(target, baseline, integrity)
        n_defence = write_baseline(defence_target, defence_baseline, integrity)
        reason = "updated explicitly" if rebaseline else "initialised (first start; no prior audit history)"
        # Keep a stable, human-readable marker for operational smoke checks while naming both trees.
        out(f"defence: baseline {reason} - HYDRA inventory: {n_hydra} files; defence inventory: {n_defence} files")

    clean_hydra = None
    clean_defence = None
    if restore:
        try:
            clean_hydra = git_clean_source(root, HYDRA_REL)
        except Exception as e:
            out(f"defence: cannot read clean HYDRA source from git ({type(e).__name__}); recovery unavailable")
        try:
            clean_defence = git_clean_source(repo_root(), DEFENCE_REL)
        except Exception as e:
            out(f"defence: cannot read clean defence source from git ({type(e).__name__}); recovery unavailable")
    os.makedirs(audit_dir, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    try:
        rc = launcher.run(
            args, hydra_main=vetted, key_provider=provider, out=out, hydra_dir=target,
            baseline_path=baseline, clean_source=clean_hydra,
            defence_dir=defence_target, defence_baseline_path=defence_baseline,
            defence_clean_source=clean_defence,
            audit_file=os.path.join(audit_dir, f"{stamp}.jsonl"),
        )
    finally:
        clean_roots = {
            os.path.dirname(os.path.dirname(p))
            for p in (clean_hydra, clean_defence) if p
        }
        for temp_root in clean_roots:
            shutil.rmtree(temp_root, ignore_errors=True)
    if rc == 4 and restore:
        out("defence: execution refused after recovery/check. If files were restored, rerun the command without --defence-restore so Python loads the verified on-disk code.")
    elif rc == 4:
        out("defence: code differs from the trusted baseline or a signed baseline is invalid/missing. "
            "If you changed code intentionally use --defence-rebaseline; to undo unwanted changes use --defence-restore.")
    return rc


def enforce(argv: Optional[Sequence[str]] = None, *, root: Optional[str] = None, out=print) -> None:
    """Hook for every HYDRA entry point (CLI main, UI...): the defence runs first, always, in-process.
    Refused -> SystemExit(code); HYDRA never continues. No-op if the defence already vetted this process."""
    global ACTIVE
    if ACTIVE:
        return
    rc = main(argv, root=root, hydra_main=lambda a: 0, out=out)
    if rc != 0:
        raise SystemExit(rc)
    ACTIVE = True
