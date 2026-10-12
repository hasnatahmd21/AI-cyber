"""Gate 1 - outer barrier: first enforcement point for every untrusted request."""
from __future__ import annotations

import re
import threading
import time
from urllib.parse import unquote
from typing import Any, Callable, Dict, Optional, Tuple

from .contracts import AuditSink, Decision, Finding, LayerResult, Request
from .trust_authority import TrustAuthority

ALLOWED_ACTIONS = frozenset({"read", "write", "delete", "list", "execute", "run"})
MAX_ID_LEN = 128
MAX_RESOURCE_LEN = 512
MAX_PAYLOAD_BYTES = 1_000_000
_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]+$")
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class RateLimiter:
    """Thread-safe token bucket per principal."""
    def __init__(self, capacity: int = 20, refill_per_sec: float = 5.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        if not isinstance(refill_per_sec, (int, float)) or isinstance(refill_per_sec, bool) or refill_per_sec <= 0:
            raise ValueError("refill_per_sec must be positive")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self.capacity, self.rate, self._clock = capacity, float(refill_per_sec), clock
        self._b: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self._lock:
            now = self._clock()
            tokens, last = self._b.get(key, (float(self.capacity), now))
            # A clock moving backwards must not mint extra tokens.
            elapsed = max(0.0, now - last)
            tokens = min(float(self.capacity), tokens + elapsed * self.rate)
            if tokens < 1:
                self._b[key] = (tokens, max(now, last))
                return False
            self._b[key] = (tokens - 1, max(now, last))
            return True


class Barrier:
    name = "barrier"

    def __init__(self, trust: TrustAuthority, limiter: Optional[RateLimiter] = None,
                 audit: Optional[AuditSink] = None) -> None:
        self.trust, self.limiter, self.audit = trust, limiter if limiter is not None else RateLimiter(), audit

    def _record(self, event: str, **fields: Any) -> bool:
        if self.audit is None:
            return True
        try:
            self.audit.record(event, **fields)
            return True
        except Exception:
            return False

    def _deny(self, req_id: str, code: str, detail: str,
              d: Decision = Decision.BLOCK) -> LayerResult:
        # Audit failure must never turn a denial into an exception or an allow.
        self._record("barrier_reject", request_id=req_id, code=code)
        return LayerResult(self.name, d, (Finding(self.name, code, 8, detail),), reason=code)

    @staticmethod
    def _payload_size(p: Any) -> int:
        if p is None:
            return 0
        if isinstance(p, (bytes, bytearray, memoryview)):
            return len(p)
        return len(str(p).encode("utf-8", "replace"))

    @staticmethod
    def _has_path_traversal(resource: str) -> bool:
        """Fail closed on traversal, malformed escapes, invalid UTF-8, or excessive decoding."""
        current = resource
        for _ in range(6):
            current = current.replace("\\", "/")
            if ".." in current.split("/"):
                return True
            if _BAD_PERCENT_RE.search(current):
                return True
            try:
                decoded = unquote(current, errors="strict")
            except (UnicodeDecodeError, ValueError):
                return True
            if decoded == current:
                return False
            current = decoded
        # Still changing after the bounded decode budget: ambiguous encoding.
        return True

    def evaluate(self, req: Any, prior: Tuple[LayerResult, ...] = ()) -> LayerResult:
        # 1. Structural validation: invalid state is never authorized.
        if not isinstance(req, Request):
            return self._deny("?", "invalid_type", "not a Request", Decision.ERROR)
        for fname in ("request_id", "principal", "action", "resource"):
            v = getattr(req, fname)
            if not isinstance(v, str) or not v:
                return self._deny(str(getattr(req, "request_id", "?")), f"missing_{fname}", fname, Decision.ERROR)
        if len(req.request_id) > MAX_ID_LEN or not _ID_RE.fullmatch(req.request_id) \
                or len(req.principal) > MAX_ID_LEN or not _ID_RE.fullmatch(req.principal):
            return self._deny(req.request_id, "bad_identifier", "illegal chars/length")
        if req.action not in ALLOWED_ACTIONS:
            return self._deny(req.request_id, "action_not_allowed", req.action)
        if len(req.resource) > MAX_RESOURCE_LEN or "\x00" in req.resource:
            return self._deny(req.request_id, "bad_resource", "length/NUL")
        if self._has_path_traversal(req.resource):
            return self._deny(req.request_id, "path_traversal", req.resource)
        try:
            if self._payload_size(req.payload) > MAX_PAYLOAD_BYTES:
                return self._deny(req.request_id, "payload_too_large", "")
        except Exception:
            return self._deny(req.request_id, "payload_validation_error", "", Decision.ERROR)

        # 2. Abuse control. Dependency failure is an ERROR, never an allow.
        try:
            if not self.limiter.allow(req.principal):
                return self._deny(req.request_id, "rate_limited", req.principal)
        except Exception:
            return self._deny(req.request_id, "rate_limiter_error", "", Decision.ERROR)

        # 3. Authentication + authorization. Treat exceptions as fail-closed errors.
        try:
            if not self.trust.authenticate(req.principal, req.credentials):
                return self._deny(req.request_id, "auth_failed", req.principal)
            if not self.trust.is_permitted(req):
                return self._deny(req.request_id, "not_permitted", f"{req.action}:{req.resource}")
        except Exception:
            return self._deny(req.request_id, "trust_dependency_error", "", Decision.ERROR)

        # If an allow cannot be recorded, do not allow the request through.
        if not self._record("barrier_allow", request_id=req.request_id):
            return LayerResult(self.name, Decision.ERROR,
                               (Finding(self.name, "audit_failure", 8, "allow audit failed"),),
                               reason="audit_failure")
        return LayerResult(self.name, Decision.ALLOW, reason="ok")
