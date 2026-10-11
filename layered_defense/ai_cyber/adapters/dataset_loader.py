"""Read-only, integrity-checked dataset access.

Expected layout (one dataset dir, e.g. datasets/raw/<n>/):
    manifest.json   {"files": [{"path": "rules.json", "sha256": "<hex>"}, ...]}
Every file is hash-verified BEFORE its content is returned. Any problem -> DatasetIntegrityError
(fail closed). Paths that escape the dataset dir are rejected. Nothing is ever written.
NOTE: if your real manifests use another shape, change only _read_manifest()."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Tuple

from ..contracts import SecurityError
from ..crypto_integrity import verify_file_hash

MAX_FILE_BYTES = 50 * 1024 * 1024


class DatasetIntegrityError(SecurityError):
    pass


@dataclass(frozen=True)
class VerifiedDataset:
    root: str
    files: Tuple[Tuple[str, str], ...]          # (relative path, sha256)

    def read_bytes(self, rel: str) -> bytes:
        if rel not in dict(self.files):
            raise DatasetIntegrityError(f"file not in verified manifest: {rel}")
        p = _safe_path(self.root, rel)
        if not verify_file_hash(p, dict(self.files)[rel]):   # re-check at read time (TOCTOU)
            raise DatasetIntegrityError(f"hash mismatch at read: {rel}")
        with open(p, "rb") as f:
            return f.read()

    def read_json(self, rel: str):
        try:
            return json.loads(self.read_bytes(rel).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise DatasetIntegrityError(f"invalid json: {rel}") from e


def _safe_path(root: str, rel: str) -> str:
    base = os.path.realpath(root)
    p = os.path.realpath(os.path.join(base, rel))
    if os.path.commonpath([base, p]) != base:
        raise DatasetIntegrityError(f"path escapes dataset dir: {rel}")
    return p


def _read_manifest(root: str) -> List[Tuple[str, str]]:
    mp = os.path.join(root, "manifest.json")
    try:
        with open(mp, encoding="utf-8") as f:
            m = json.load(f)
        out = [(str(e["path"]), str(e["sha256"]).lower()) for e in m["files"]]
    except Exception as e:
        raise DatasetIntegrityError(f"manifest unreadable/invalid: {type(e).__name__}") from e
    if not out:
        raise DatasetIntegrityError("manifest lists no files")
    return out


def load_verified(root: str) -> VerifiedDataset:
    entries = _read_manifest(root)
    for rel, digest in entries:
        p = _safe_path(root, rel)
        if not os.path.isfile(p) or os.path.getsize(p) > MAX_FILE_BYTES:
            raise DatasetIntegrityError(f"missing or oversized: {rel}")
        if not verify_file_hash(p, digest):
            raise DatasetIntegrityError(f"sha256 mismatch: {rel}")
    return VerifiedDataset(os.path.realpath(root), tuple(entries))
