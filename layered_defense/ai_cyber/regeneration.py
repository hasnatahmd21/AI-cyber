"""Verified-clean recovery. Never copies untrusted state: the baseline is MAC-signed, the
clean source is verified against it BEFORE use, and the result is re-verified after."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from typing import Dict, List

from .crypto_integrity import Integrity
from .contracts import SecurityError


class RegenerationError(SecurityError):
    pass


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _validate_baseline(baseline: Dict[str, str]) -> None:
    """Validate manifest paths and hashes before using either in filesystem operations."""
    if not isinstance(baseline, dict) or not baseline:
        raise RegenerationError("baseline must be a non-empty mapping")
    for rel, digest in baseline.items():
        if not isinstance(rel, str) or not rel or "\\" in rel or rel.startswith("/"):
            raise RegenerationError("invalid relative path in baseline")
        parts = rel.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise RegenerationError("path escape in baseline")
        if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
            raise RegenerationError("invalid SHA-256 digest in baseline")


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def build_baseline(root: str) -> Dict[str, str]:
    """Hash regular files only; reject links, hard-linked files and special filesystem nodes."""
    if os.path.islink(root):
        raise RegenerationError("root may not be a symbolic link")
    if not os.path.isdir(root):
        return {}
    out: Dict[str, str] = {}
    for dp, dn, fn in os.walk(root, followlinks=False):
        for directory in list(dn):
            candidate = os.path.join(dp, directory)
            if os.path.islink(candidate):
                raise RegenerationError(f"symbolic link is not permitted: {os.path.relpath(candidate, root)}")
            if directory == "__pycache__":
                dn.remove(directory)
        for f in sorted(fn):
            p = os.path.join(dp, f)
            try:
                info = os.lstat(p)
            except OSError as exc:
                raise RegenerationError("tree changed during inventory") from exc
            if not stat.S_ISREG(info.st_mode):
                raise RegenerationError(f"non-regular file is not permitted: {os.path.relpath(p, root)}")
            if info.st_nlink > 1:
                raise RegenerationError(f"hard-linked file is not permitted: {os.path.relpath(p, root)}")
            # Only __pycache__ directories are excluded. An orphan .pyc elsewhere can be
            # importable, so it is inventoried like every other regular file.
            out[os.path.relpath(p, root).replace(os.sep, "/")] = _sha(p)
    return out


def sign_baseline(baseline: Dict[str, str], integrity: Integrity) -> str:
    _validate_baseline(baseline)
    return integrity.sign(json.dumps(baseline, sort_keys=True).encode())


def verify_tree(root: str, baseline: Dict[str, str]) -> List[str]:
    """Detect modified, missing AND unexpected files; empty list means exact file-set match."""
    _validate_baseline(baseline)
    actual = build_baseline(root)
    bad = []
    for rel, digest in baseline.items():
        if rel not in actual:
            bad.append(f"missing:{rel}")
        elif actual[rel] != digest:
            bad.append(f"modified:{rel}")
    for rel in sorted(set(actual) - set(baseline)):
        bad.append(f"unexpected:{rel}")
    return sorted(bad)


def _replace_from_clean_source(src: str, dest: str) -> None:
    """Write to a fresh inode and atomically replace the path; never truncate a hard link."""
    parent = os.path.dirname(dest)
    os.makedirs(parent, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".aicyber-recovery-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as output, open(src, "rb") as source:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        shutil.copystat(src, temporary, follow_symlinks=False)
        os.replace(temporary, dest)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def regenerate(target: str, clean_source: str, baseline: Dict[str, str], signature: str,
               integrity: Integrity) -> List[str]:
    """Restore missing/modified files and remove unexpected files only from a verified clean source."""
    _validate_baseline(baseline)
    if not integrity.verify(json.dumps(baseline, sort_keys=True).encode(), signature):
        raise RegenerationError("baseline signature invalid - refusing to regenerate")
    src_problems = verify_tree(clean_source, baseline)
    if src_problems:
        raise RegenerationError(f"clean source is not clean: {src_problems[:3]}")
    problems = verify_tree(target, baseline)
    changed = []
    target_root = os.path.abspath(target)
    for problem in problems:
        kind, rel = problem.split(":", 1)
        # Baseline paths have been validated and are relative POSIX paths.
        dest = os.path.abspath(os.path.join(target_root, *rel.split("/")))
        if os.path.commonpath((target_root, dest)) != target_root or dest == target_root:
            raise RegenerationError("path escape in baseline")
        if kind == "unexpected":
            # Inventory already proved this is a regular, non-hard-linked file.
            if os.path.islink(dest) or not os.path.isfile(dest):
                raise RegenerationError(f"unexpected path is not a regular file: {rel}")
            os.remove(dest)  # unlinking a name does not modify the linked inode's content
            changed.append(f"removed:{rel}")
        elif kind in ("missing", "modified"):
            src = os.path.join(clean_source, *rel.split("/"))
            _replace_from_clean_source(src, dest)
            changed.append(rel)
        else:
            raise RegenerationError(f"unknown integrity finding: {kind}")
    post = verify_tree(target, baseline)
    if post:
        raise RegenerationError(f"post-recovery verification failed: {post[:3]}")
    return changed
