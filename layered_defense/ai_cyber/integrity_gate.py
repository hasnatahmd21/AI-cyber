"""Signed integrity checks for HYDRA and the defence implementation itself.

Recovery is explicit, uses only a clean source that matches the signed baseline, and
always blocks the current process after writing files: already-imported Python code is
not replaced by repairing files on disk. Restart after a restore to load the recovered code.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

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
    parent = os.path.dirname(os.path.abspath(baseline_path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    tmp = baseline_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"baseline": bl, "signature": sign_baseline(bl, integrity)}, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, baseline_path)
    return len(bl)


def _read_signed(path: str, integrity: Integrity, audit, scope: str) -> Tuple[Optional[dict], Optional[str], Optional[str]]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        if not isinstance(doc, dict):
            raise ValueError("baseline document must be an object")
        bl, sig = doc.get("baseline"), doc.get("signature")
        if not isinstance(bl, dict) or not isinstance(sig, str):
            raise ValueError("baseline fields missing or malformed")
        if not integrity.verify(json.dumps(bl, sort_keys=True).encode(), sig):
            audit.record("integrity_failed", scope=scope, problems=["bad_signature"])
            return None, None, f"{scope} baseline signature invalid"
        return bl, sig, None
    except Exception as exc:
        audit.record("integrity_failed", scope=scope, problems=["missing_or_unreadable", type(exc).__name__])
        return None, None, f"{scope} baseline missing/unreadable - explicit rebaseline required"


def _inspect_tree(target: str, baseline: dict, audit, scope: str):
    try:
        return verify_tree(target, baseline), None
    except (RegenerationError, OSError, ValueError) as exc:
        audit.record("integrity_failed", scope=scope + "_tree_inventory", problems=[type(exc).__name__])
        return None, f"{scope} code tree could not be safely inspected"


def check(system: System, target: str, baseline_path: str, integrity: Integrity,
          clean_source: Optional[str] = None, *, defence_dir: Optional[str] = None,
          defence_baseline_path: Optional[str] = None,
          defence_clean_source: Optional[str] = None) -> GateResult:
    """Verify both signed trees; never execute a process after restoring on-disk code."""
    audit = system.audit
    if not defence_dir or not defence_baseline_path:
        audit.record("integrity_failed", scope="defence_baseline", problems=["missing_configuration"])
        return GateResult(False, "defence code integrity configuration missing")

    # Validate both signatures and both file inventories BEFORE altering any file.
    h_bl, h_sig, err = _read_signed(baseline_path, integrity, audit, "hydra_baseline")
    if err:
        return GateResult(False, err)
    d_bl, d_sig, err = _read_signed(defence_baseline_path, integrity, audit, "defence_baseline")
    if err:
        return GateResult(False, err)

    h_problems, err = _inspect_tree(target, h_bl, audit, "hydra")
    if err:
        return GateResult(False, err)
    d_problems, err = _inspect_tree(defence_dir, d_bl, audit, "defence")
    if err:
        return GateResult(False, err)

    needs_hydra = bool(h_problems)
    needs_defence = bool(d_problems)
    if needs_hydra or needs_defence:
        audit.record("integrity_drift", hydra_problems=h_problems[:10], defence_problems=d_problems[:10])
        if needs_hydra and not clean_source:
            return GateResult(False, f"HYDRA code changed ({len(h_problems)} files) and no clean source given")
        if needs_defence and not defence_clean_source:
            return GateResult(False, f"defence implementation changed ({len(d_problems)} files) and no clean source given")

        # Validate every recovery source before restoring either tree, preventing partial recovery
        # when one clean source is missing, contaminated, or linked through an unsafe filesystem entry.
        try:
            if needs_hydra:
                source_problems = verify_tree(clean_source, h_bl)
                if source_problems:
                    raise RegenerationError(f"HYDRA recovery source differs from baseline: {source_problems[:3]}")
            if needs_defence:
                source_problems = verify_tree(defence_clean_source, d_bl)
                if source_problems:
                    raise RegenerationError(f"defence recovery source differs from baseline: {source_problems[:3]}")
        except (RegenerationError, OSError, ValueError) as exc:
            audit.record("regeneration_failed", error=str(exc)[:200])
            return GateResult(False, f"regeneration refused: {exc}")

        restored: List[str] = []
        try:
            if needs_defence:
                paths = regenerate(defence_dir, defence_clean_source, d_bl, d_sig, integrity)
                restored.extend("defence:" + p for p in paths)
            if needs_hydra:
                paths = regenerate(target, clean_source, h_bl, h_sig, integrity)
                restored.extend("hydra:" + p for p in paths)
        except (RegenerationError, OSError, ValueError) as exc:
            audit.record("regeneration_failed", error=str(exc)[:200])
            return GateResult(False, f"regeneration refused: {exc}", restored)

        audit.record("regenerated", files=restored[:40], count=len(restored), restart_required=True)
        return GateResult(False, "trusted files restored; restart required before execution", restored)

    # The split/concatenation check is independent from the signed trees and remains mandatory.
    try:
        bad = system.hydra.verify_files()
        lossless = system.hydra.verify_lossless()
    except Exception as exc:
        audit.record("integrity_failed", scope="defence_legacy", problems=[type(exc).__name__])
        return GateResult(False, "defence legacy files could not be verified")
    if bad or not lossless:
        audit.record("integrity_failed", scope="defence_legacy", problems=bad[:5])
        return GateResult(False, "defence legacy files damaged")

    audit.record("integrity_ok", hydra_files=len(h_bl), defence_files=len(d_bl))
    return GateResult(True, "clean")
