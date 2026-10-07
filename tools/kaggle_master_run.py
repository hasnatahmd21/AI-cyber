#!/usr/bin/env python3
"""One-command Kaggle master runner: acquire datasets, then fresh-verify the result."""
from __future__ import annotations

import os
import subprocess
import sys


def main() -> int:
    env = os.environ.copy()
    env.setdefault("AI_CYBER_BRANCH", "repair/forensic-reconstruction")
    env.setdefault("AI_CYBER_REPO", "hasnatahmd21/AI-cyber")
    env.setdefault("DATASET_FAMILIES", "all")
    env.setdefault("PUSH_DATASETS", "1")
    env.setdefault("GIT_LFS_THRESHOLD_MB", "50")

    print("=" * 88)
    print("AI-CYBER — KAGGLE MASTER: ACQUIRE → PUSH → FRESH VERIFY")
    print("=" * 88)

    acquire = subprocess.run(
        [sys.executable, "tools/kaggle_acquire_datasets.py"],
        env=env,
        check=False,
    )
    if acquire.returncode != 0:
        print("MASTER RESULT: acquisition failed/failed-closed; verification was not run.")
        return acquire.returncode

    verify = subprocess.run(
        [sys.executable, "tools/kaggle_full_verification.py"],
        env=env,
        check=False,
    )
    if verify.returncode != 0:
        print("MASTER RESULT: acquisition succeeded but fresh verification failed.")
        return verify.returncode

    print("=" * 88)
    print("MASTER RESULT: PASS")
    print("Datasets acquired/pushed and fresh runtime verification passed.")
    print("=" * 88)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
