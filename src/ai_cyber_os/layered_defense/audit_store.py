"""Atomic JSONL persistence and verification for the tamper-evident audit chain."""
from __future__ import annotations
import json, os
from .audit_telemetry import AuditLog
from .contracts import SecurityError


class AuditTamperError(SecurityError): pass


def save(audit: AuditLog, path: str) -> int:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    records = audit.records()
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as stream:
        for record in records: stream.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return len(records)


def load_verified(path: str, expected_len=None):
    try:
        with open(path, encoding="utf-8") as stream: records = [json.loads(line) for line in stream if line.strip()]
    except Exception as exc: raise AuditTamperError(f"audit file unreadable: {type(exc).__name__}") from exc
    if not AuditLog.verify(records, expected_len=expected_len): raise AuditTamperError("audit chain verification failed")
    return records
