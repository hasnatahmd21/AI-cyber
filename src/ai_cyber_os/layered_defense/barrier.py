"""Outer perimeter barrier: structural validation, rate limiting and authorization."""
from __future__ import annotations
import re, time
from typing import Any, Callable, Dict, Optional, Tuple
from .contracts import AuditSink, Decision, Finding, LayerResult, Request
from .trust_authority import TrustAuthority

ALLOWED_ACTIONS = frozenset({"read", "write", "delete", "list", "execute", "run"})
_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]+$")
MAX_PAYLOAD_BYTES = 1_000_000


class RateLimiter:
    def __init__(self, capacity: int = 20, refill_per_sec: float = 5.0, clock: Callable[[], float] = time.monotonic):
        if capacity < 1 or refill_per_sec <= 0:
            raise ValueError("rate limit settings must be positive")
        self.capacity, self.rate, self._clock = capacity, refill_per_sec, clock
        self._b: Dict[str, Tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = self._clock()
        tokens, last = self._b.get(key, (float(self.capacity), now))
        tokens = min(self.capacity, tokens + max(0.0, now - last) * self.rate)
        if tokens < 1:
            self._b[key] = (tokens, now)
            return False
        self._b[key] = (tokens - 1, now)
        return True


class Barrier:
    name = "barrier"
    def __init__(self, trust: TrustAuthority, limiter: Optional[RateLimiter] = None, audit: Optional[AuditSink] = None):
        self.trust, self.limiter, self.audit = trust, limiter or RateLimiter(), audit

    def _deny(self, rid: str, code: str, detail: str, decision: Decision = Decision.BLOCK) -> LayerResult:
        if self.audit:
            self.audit.record("barrier_reject", request_id=rid, code=code)
        return LayerResult(self.name, decision, (Finding(self.name, code, 8, detail),), code)

    @staticmethod
    def _size(payload: Any) -> int:
        if payload is None: return 0
        if isinstance(payload, (bytes, bytearray)): return len(payload)
        return len(str(payload).encode("utf-8", "replace"))

    def evaluate(self, req: Any, prior: Tuple[LayerResult, ...] = ()) -> LayerResult:
        if not isinstance(req, Request):
            return self._deny("?", "invalid_type", "request is not a Request", Decision.ERROR)
        for name in ("request_id", "principal", "action", "resource"):
            value = getattr(req, name)
            if not isinstance(value, str) or not value:
                return self._deny("?", f"missing_{name}", name, Decision.ERROR)
        if len(req.request_id) > 128 or not _ID_RE.fullmatch(req.request_id) or len(req.principal) > 128 or not _ID_RE.fullmatch(req.principal):
            return self._deny(req.request_id, "bad_identifier", "illegal characters or length")
        if req.action not in ALLOWED_ACTIONS:
            return self._deny(req.request_id, "action_not_allowed", req.action)
        if len(req.resource) > 512 or "\x00" in req.resource:
            return self._deny(req.request_id, "bad_resource", "length or NUL")
        if ".." in req.resource.replace("\\", "/").split("/"):
            return self._deny(req.request_id, "path_traversal", req.resource)
        if self._size(req.payload) > MAX_PAYLOAD_BYTES:
            return self._deny(req.request_id, "payload_too_large", "")
        if not self.limiter.allow(req.principal):
            return self._deny(req.request_id, "rate_limited", req.principal)
        if not self.trust.authenticate(req.principal, req.credentials) or not self.trust.is_permitted(req):
            return self._deny(req.request_id, "not_authorized", req.action)
        if self.audit: self.audit.record("barrier_allow", request_id=req.request_id)
        return LayerResult(self.name, Decision.ALLOW, reason="ok")
