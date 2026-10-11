"""Atomic JSONL persistence with signed count/final-hash manifests."""
from __future__ import annotations
import json, os
from typing import Optional
from .audit_telemetry import AuditLog
from .contracts import SecurityError
from .crypto_integrity import Integrity

_GENESIS = "0" * 64


class AuditTamperError(SecurityError): pass


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _has_symlink_ancestor(path: str) -> bool:
    current = os.path.abspath(path)
    while True:
        if os.path.islink(current):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def _atomic_write(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    temporary = path + ".tmp"
    if _has_symlink_ancestor(directory) or os.path.islink(path) or os.path.islink(temporary):
        raise AuditTamperError("refusing symlinked audit persistence path")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = None
    created = False
    try:
        fd = os.open(temporary, flags, 0o600)
        created = True
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory_fd = os.open(directory, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd is not None:
            os.close(fd)
        if created:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def save(audit: AuditLog, path: str, *, integrity: Optional[Integrity] = None) -> int:
    """Persist a chain without overwriting a tampered or divergent prior chain."""
    directory = os.path.dirname(os.path.abspath(path))
    if _has_symlink_ancestor(directory):
        raise AuditTamperError("refusing audit persistence through a symlinked directory")
    os.makedirs(directory, exist_ok=True)
    if _has_symlink_ancestor(directory):
        raise AuditTamperError("audit persistence directory became a symlink")
    manifest_path = path + ".manifest.json"
    if os.path.islink(path) or os.path.islink(manifest_path):
        raise AuditTamperError("refusing symlinked audit chain or manifest")

    records = audit.records()
    chain_exists = os.path.lexists(path)
    manifest_exists = os.path.lexists(manifest_path)
    if chain_exists or manifest_exists:
        if not chain_exists or not manifest_exists:
            raise AuditTamperError("persisted audit chain/manifest pair is incomplete")
        existing = load_verified(path, integrity=integrity)
        if len(existing) > len(records):
            raise AuditTamperError("persisted audit contains records absent from memory")
        previous_hashes = [record.get("hash") for record in existing]
        current_hashes = [record.get("hash") for record in records[:len(existing)]]
        if previous_hashes != current_hashes:
            raise AuditTamperError("persisted audit history diverges from in-memory chain")

    lines = "".join(json.dumps(record, sort_keys=True, default=str) + "\n" for record in records)
    manifest = {
        "count": len(records),
        "final_hash": records[-1]["hash"] if records else _GENESIS,
    }
    document = {"manifest": manifest}
    if integrity is not None:
        document["signature"] = integrity.sign(_canonical(manifest))
    # Chain first, manifest second. A crash between these writes is detected by the
    # next save instead of silently replacing the previous signed history.
    _atomic_write(path, lines)
    _atomic_write(manifest_path, json.dumps(document, sort_keys=True, indent=2))
    return len(records)


def load_verified(path: str, expected_len=None, *, integrity: Optional[Integrity] = None):
    try:
        with open(path, encoding="utf-8") as stream:
            records = [json.loads(line) for line in stream if line.strip()]
        with open(path + ".manifest.json", encoding="utf-8") as stream:
            document = json.load(stream)
        manifest = document["manifest"]
    except Exception as exc:
        raise AuditTamperError(f"audit file or manifest unreadable: {type(exc).__name__}") from exc
    if not AuditLog.verify(records, expected_len=expected_len):
        raise AuditTamperError("audit chain verification failed")
    if manifest.get("count") != len(records):
        raise AuditTamperError("audit record count does not match manifest")
    final_hash = records[-1]["hash"] if records else _GENESIS
    if manifest.get("final_hash") != final_hash:
        raise AuditTamperError("audit final hash does not match manifest")
    signature = document.get("signature")
    if integrity is not None and not isinstance(signature, str):
        raise AuditTamperError("audit manifest signature missing")
    if signature is not None:
        if integrity is None or not integrity.verify(_canonical(manifest), signature):
            raise AuditTamperError("audit manifest signature invalid or verifier missing")
    return records
