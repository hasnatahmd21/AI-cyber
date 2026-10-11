"""Persist the tamper-evident audit chain to disk (JSONL) and verify it on load."""
from __future__ import annotations

import json
import os

from ..audit_telemetry import AuditLog
from ..contracts import SecurityError


class AuditTamperError(SecurityError):
    pass


def save(audit: AuditLog, path: str) -> int:
    recs = audit.records()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, sort_keys=True, default=str) + "\n")
    os.replace(tmp, path)                           # atomic: never leaves a half-written log
    return len(recs)


def load_verified(path: str, expected_len=None):
    try:
        with open(path, encoding="utf-8") as f:
            recs = [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        raise AuditTamperError(f"audit file unreadable: {type(e).__name__}") from e
    if not AuditLog.verify(recs, expected_len=expected_len):
        raise AuditTamperError("audit chain verification failed")
    return recs
