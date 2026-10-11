"""Verified-clean recovery. Never copies untrusted state: the baseline is MAC-signed, the
clean source is verified against it BEFORE use, and the result is re-verified after."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from typing import Dict, List

from .crypto_integrity import Integrity
from .contracts import SecurityError


class RegenerationError(SecurityError):
    pass


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def build_baseline(root: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for dp, dn, fn in os.walk(root):
        dn[:] = sorted(d for d in dn if d != "__pycache__")
        for f in sorted(fn):
            if f.endswith(".pyc"):
                continue
            p = os.path.join(dp, f)
            out[os.path.relpath(p, root).replace(os.sep, "/")] = _sha(p)
    return out


def sign_baseline(baseline: Dict[str, str], integrity: Integrity) -> str:
    return integrity.sign(json.dumps(baseline, sort_keys=True).encode())


def verify_tree(root: str, baseline: Dict[str, str]) -> List[str]:
    """Returns list of problems (missing/modified files). Empty list == clean."""
    bad = []
    for rel, digest in baseline.items():
        p = os.path.join(root, *rel.split("/"))
        if not os.path.isfile(p):
            bad.append(f"missing:{rel}")
        elif _sha(p) != digest:
            bad.append(f"modified:{rel}")
    return bad


def regenerate(target: str, clean_source: str, baseline: Dict[str, str], signature: str,
               integrity: Integrity) -> List[str]:
    """Restore damaged/missing files in `target` from `clean_source`. Returns restored files."""
    if not integrity.verify(json.dumps(baseline, sort_keys=True).encode(), signature):
        raise RegenerationError("baseline signature invalid - refusing to regenerate")
    src_problems = verify_tree(clean_source, baseline)
    if src_problems:
        raise RegenerationError(f"clean source is not clean: {src_problems[:3]}")
    restored = []
    for rel in verify_tree(target, baseline):
        rel = rel.split(":", 1)[1]
        # path safety: only baseline-listed relative paths, never outside target
        dest = os.path.normpath(os.path.join(target, *rel.split("/")))
        if not dest.startswith(os.path.normpath(target) + os.sep):
            raise RegenerationError("path escape in baseline")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(os.path.join(clean_source, *rel.split("/")), dest)
        restored.append(rel)
    post = verify_tree(target, baseline)
    if post:
        raise RegenerationError(f"post-recovery verification failed: {post[:3]}")
    return restored
