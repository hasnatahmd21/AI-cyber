"""Tamper-evident audit log (hash chain) with secret redaction."""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from typing import Any, Dict, List, Optional

_SECRET_KEYS = re.compile(r"(secret|token|password|passwd|api[_-]?key|credential|private[_-]?key)", re.I)
_GENESIS = "0" * 64


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if _SECRET_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def _digest(prev: str, body: Dict[str, Any]) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, default=str)).encode()).hexdigest()


class AuditLog:
    def __init__(self, clock=time.time) -> None:
        self._records: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._clock = clock
        self.health_errors = 0

    def record(self, event: str, **fields: Any) -> None:
        try:
            with self._lock:
                prev = self._records[-1]["hash"] if self._records else _GENESIS
                body = {"seq": len(self._records), "ts": self._clock(), "event": str(event),
                        "fields": redact(fields)}
                body["prev"] = prev
                body["hash"] = _digest(prev, {k: v for k, v in body.items() if k not in ("hash",)})
                self._records.append(body)
        except Exception:  # audit must never break the request path, but failure is counted
            self.health_errors += 1

    def records(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._records]

    @staticmethod
    def verify(records: Any, expected_len: Optional[int] = None) -> bool:
        """Verify chain. Never raises; malformed input -> False."""
        try:
            if not isinstance(records, (list, tuple)):
                return False
            if expected_len is not None and len(records) != expected_len:
                return False  # head/tail truncation
            prev = _GENESIS
            for i, r in enumerate(records):
                if not isinstance(r, dict) or r.get("seq") != i or r.get("prev") != prev:
                    return False
                body = {k: v for k, v in r.items() if k != "hash"}
                if _digest(prev, body) != r.get("hash"):
                    return False
                prev = r["hash"]
            return True
        except Exception:
            return False

    def self_verify(self) -> bool:
        recs = self.records()
        return self.verify(recs, expected_len=len(recs))

    def health(self) -> Dict[str, Any]:
        return {"records": len(self._records), "errors": self.health_errors, "chain_ok": self.self_verify()}
