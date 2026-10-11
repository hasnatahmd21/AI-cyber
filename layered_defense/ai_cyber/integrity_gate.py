"""Startup integrity + recovery for the code HYDRA runs from (and the defence's own legacy copy).

  baseline  : create/update a MAC-signed hash baseline of the HYDRA code dir (deliberate, operator action)
  check     : verify tree against the signed baseline; bad signature / drift -> not clean
  recover   : drift + a clean source given -> regeneration.regenerate (verified before AND after use)
Fail closed: unsigned/missing/invalid baseline or unrecoverable drift means HYDRA is NOT started."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

from .crypto_integrity import Integrity
from .regeneration import RegenerationError, build_baseline, regenerate, sign_baseline, verify_tree
from .runtime import System


@dataclass
class GateResult:
    ok: bool
    reason: str
    restored: List[str] = field(default_factory=list)


def write_baseline(target: str, baseline_path: str, integrity: Integrity) -> int:
    bl = build_baseline(target)
    if not bl:
        raise RegenerationError("target has no files to baseline")
    os.makedirs(os.path.dirname(os.path.abspath(baseline_path)), exist_ok=True)
    tmp = baseline_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"baseline": bl, "signature": sign_baseline(bl, integrity)}, f, indent=1, sort_keys=True)
    os.replace(tmp, baseline_path)
    return len(bl)


def check(system: System, target: str, baseline_path: str, integrity: Integrity,
          clean_source: Optional[str] = None) -> GateResult:
    a = system.audit
    # 1) defence's own HYDRA-split files must match their manifest and reassemble to the original
    bad = system.hydra.verify_files()
    if bad or not system.hydra.verify_lossless():
        a.record("integrity_failed", scope="defence_legacy", problems=bad[:5])
        return GateResult(False, "defence legacy files damaged")
    # 2) HYDRA code tree vs signed baseline
    try:
        with open(baseline_path, encoding="utf-8") as f:
            doc = json.load(f)
        bl, sig = doc["baseline"], doc["signature"]
    except Exception:
        a.record("integrity_failed", scope="baseline", problems=["missing_or_unreadable"])
        return GateResult(False, "baseline missing/unreadable - create it first (python -m ai_cyber baseline)")
    if not integrity.verify(json.dumps(bl, sort_keys=True).encode(), sig):
        a.record("integrity_failed", scope="baseline", problems=["bad_signature"])
        return GateResult(False, "baseline signature invalid")
    try:
        problems = verify_tree(target, bl)
    except RegenerationError as e:
        # Uninspectable trees (including symbolic-link entries) must block execution cleanly.
        a.record("integrity_failed", scope="tree_inventory", problems=[type(e).__name__])
        return GateResult(False, "HYDRA code tree could not be safely inspected")
    if not problems:
        a.record("integrity_ok", files=len(bl))
        return GateResult(True, "clean")
    a.record("integrity_drift", problems=problems[:10])
    if not clean_source:
        return GateResult(False, f"HYDRA code changed ({len(problems)} files) and no clean source given")
    try:
        restored = regenerate(target, clean_source, bl, sig, integrity)
    except RegenerationError as e:
        a.record("regeneration_failed", error=str(e)[:200])
        return GateResult(False, f"regeneration refused: {e}")
    a.record("regenerated", files=restored[:20], count=len(restored))
    return GateResult(True, "regenerated", restored)
