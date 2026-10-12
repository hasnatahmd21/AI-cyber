"""Persist tamper-evident audit chains as plaintext JSONL or authenticated ciphertext."""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from ..audit_telemetry import AuditLog
from ..contracts import SecurityError
from ..crypto_encryption import AeadCipher

_AUDIT_AAD = b"ai-cyber/audit-log/v1"


class AuditTamperError(SecurityError):
    pass


def _records(audit: AuditLog) -> list[dict[str, Any]]:
    return audit.records()


def save(audit: AuditLog, path: str) -> int:
    """Legacy plaintext persistence for explicit callers/tests; prefer save_encrypted at runtime."""
    recs = _records(audit)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, sort_keys=True, default=str) + "\\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return len(recs)


def load_verified(path: str, expected_len=None):
    """Load and verify a plaintext JSONL audit chain."""
    try:
        with open(path, encoding="utf-8") as f:
            recs = [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        raise AuditTamperError(f"audit file unreadable: {type(e).__name__}") from e
    if not AuditLog.verify(recs, expected_len=expected_len):
        raise AuditTamperError("audit chain verification failed")
    return recs


def save_encrypted(audit: AuditLog, path: str, cipher: AeadCipher) -> int:
    """Encrypt the full audit chain with AES-GCM and atomically persist mode-0600 ciphertext."""
    recs = _records(audit)
    plaintext = "".join(json.dumps(r, sort_keys=True, default=str) + "\\n" for r in recs).encode("utf-8")
    envelope = cipher.encrypt(plaintext, associated_data=_AUDIT_AAD)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".aicyber-audit-", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(envelope, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return len(recs)


def load_verified_encrypted(path: str, cipher: AeadCipher, expected_len=None):
    """Authenticate/decrypt an encrypted audit chain, then independently verify its hash chain."""
    try:
        with open(path, encoding="utf-8") as f:
            envelope = json.load(f)
        plaintext = cipher.decrypt(envelope, associated_data=_AUDIT_AAD).decode("utf-8")
        recs = [json.loads(line) for line in plaintext.splitlines() if line.strip()]
    except Exception as e:
        raise AuditTamperError(f"encrypted audit file unreadable or unauthenticated: {type(e).__name__}") from e
    if not AuditLog.verify(recs, expected_len=expected_len):
        raise AuditTamperError("audit chain verification failed")
    return recs
