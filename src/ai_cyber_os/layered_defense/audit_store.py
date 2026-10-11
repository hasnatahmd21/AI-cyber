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


def _atomic_write(path: str, text: str) -> None:
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def save(audit: AuditLog, path: str, *, integrity: Optional[Integrity] = None) -> int:
    """Persist a chain and a manifest that detects truncation and tail replacement."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    records = audit.records()
    lines = "".join(json.dumps(record, sort_keys=True, default=str) + "\n" for record in records)
    manifest = {
        "count": len(records),
        "final_hash": records[-1]["hash"] if records else _GENESIS,
    }
    document = {"manifest": manifest}
    if integrity is not None:
        document["signature"] = integrity.sign(_canonical(manifest))
    # Write the chain first. If a crash happens before the manifest replacement,
    # verification fails closed instead of silently accepting an incomplete file.
    _atomic_write(path, lines)
    _atomic_write(path + ".manifest.json", json.dumps(document, sort_keys=True, indent=2))
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
    if signature is not None:
        if integrity is None or not integrity.verify(_canonical(manifest), signature):
            raise AuditTamperError("audit manifest signature invalid or verifier missing")
    return records
