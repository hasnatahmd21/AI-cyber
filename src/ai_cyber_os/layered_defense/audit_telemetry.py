"""Tamper-evident, secret-redacting in-memory audit chain."""
from __future__ import annotations
import hashlib, json, re, threading, time
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
                body = {"seq": len(self._records), "ts": self._clock(), "event": str(event), "fields": redact(fields), "prev": prev}
                body["hash"] = _digest(prev, body)
                self._records.append(body)
        except Exception:
            self.health_errors += 1

    def records(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._records]

    @staticmethod
    def verify(records: Any, expected_len: Optional[int] = None) -> bool:
        try:
            if not isinstance(records, (list, tuple)) or (expected_len is not None and len(records) != expected_len):
                return False
            prev = _GENESIS
            for i, record in enumerate(records):
                if not isinstance(record, dict) or record.get("seq") != i or record.get("prev") != prev:
                    return False
                body = {k: v for k, v in record.items() if k != "hash"}
                if not hmac_compare(_digest(prev, body), record.get("hash", "")):
                    return False
                prev = record["hash"]
            return True
        except Exception:
            return False

    def self_verify(self) -> bool:
        records = self.records()
        return self.verify(records, expected_len=len(records))


def hmac_compare(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a, b)
