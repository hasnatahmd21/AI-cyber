"""The project's real entry: defence + HYDRA as one system.   ai-cyber [--defence-*] <hydra args>

  --defence-rebaseline   accept the current HYDRA code as the new trusted baseline (after you changed it on purpose)
  --defence-restore      restore drifted HYDRA files from git HEAD (verified against the signed baseline)
Everything else is passed to HYDRA unchanged. Key, baseline and audit logs are managed automatically in <repo>/.ai_cyber/."""
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
    audit_dir = os.path.join(state, "audit")

    if restore and rebaseline:
        out("defence: BLOCK (restore and rebaseline are mutually exclusive)")
        return 4

    baseline_missing = not os.path.exists(baseline)
    if baseline_missing and restore and not rebaseline:
        out("defence: BLOCK (restore requires an existing signed baseline; explicit rebaseline required)")
        return 4
    if baseline_missing and not rebaseline and _audit_history_exists(audit_dir):
        out("defence: BLOCK (baseline missing while prior audit history exists; explicit rebaseline required)")
        return 4

    provider = DefaultKeyProvider(state)
    if rebaseline or baseline_missing:
        n = write_baseline(target, baseline, Integrity(provider))
        out(f"defence: baseline {'updated' if rebaseline else 'initialised (first start; no prior audit history)'} - {n} HYDRA files")

    clean = None
    if restore:
        try:
            clean = git_clean_source(root)
        except Exception as e:
            out(f"defence: cannot read clean copy from git ({type(e).__name__}); restore unavailable")
    os.makedirs(audit_dir, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    try:
        rc = launcher.run(args, hydra_main=vetted, key_provider=provider, out=out, hydra_dir=target,
                          baseline_path=baseline, clean_source=clean,
                          audit_file=os.path.join(audit_dir, f"{stamp}.jsonl"))
    finally:
        if clean:
            shutil.rmtree(os.path.dirname(os.path.dirname(clean)), ignore_errors=True)
    if rc == 4:
        out("defence: HYDRA code differs from the trusted baseline. If you changed it on purpose: "
            "--defence-rebaseline. To undo unwanted changes: --defence-restore.")
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
