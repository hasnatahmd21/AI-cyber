"""Gate 1 - outer barrier: first enforcement point for every untrusted request."""
from __future__ import annotations

import re
import time
from typing import Any, Callable, Dict, Optional, Tuple

from .contracts import AuditSink, Decision, Finding, LayerResult, Request
from .trust_authority import TrustAuthority

ALLOWED_ACTIONS = frozenset({"read", "write", "delete", "list", "execute"})
MAX_ID_LEN = 128
MAX_RESOURCE_LEN = 512
MAX_PAYLOAD_BYTES = 1_000_000
_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]+$")


class RateLimiter:
    """Token bucket per principal."""
    def __init__(self, capacity: int = 20, refill_per_sec: float = 5.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.capacity, self.rate, self._clock = capacity, refill_per_sec, clock
        self._b: Dict[str, Tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = self._clock()
        tokens, last = self._b.get(key, (float(self.capacity), now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        if tokens < 1:
            self._b[key] = (tokens, now)
            return False
        self._b[key] = (tokens - 1, now)
        return True


class Barrier:
    name = "barrier"

    def __init__(self, trust: TrustAuthority, limiter: Optional[RateLimiter] = None,
                 audit: Optional[AuditSink] = None) -> None:
        self.trust, self.limiter, self.audit = trust, limiter or RateLimiter(), audit

    def _deny(self, req_id: str, code: str, detail: str, d: Decision = Decision.BLOCK) -> LayerResult:
        if self.audit:
            self.audit.record("barrier_reject", request_id=req_id, code=code)
        return LayerResult(self.name, d, (Finding(self.name, code, 8, detail),), reason=code)

    @staticmethod
    def _payload_size(p: Any) -> int:
        if p is None:
            return 0
        if isinstance(p, (bytes, bytearray)):
            return len(p)
        return len(str(p).encode("utf-8", "replace"))

    def evaluate(self, req: Any, prior: Tuple[LayerResult, ...] = ()) -> LayerResult:
        # 1. structural validation - unknown/invalid state is explicitly an error
        if not isinstance(req, Request):
            return self._deny("?", "invalid_type", "not a Request", Decision.ERROR)
        for fname in ("request_id", "principal", "action", "resource"):
            v = getattr(req, fname)
            if not isinstance(v, str) or not v:
                return self._deny(str(req.request_id), f"missing_{fname}", fname, Decision.ERROR)
        if len(req.request_id) > MAX_ID_LEN or not _ID_RE.match(req.request_id) \
                or len(req.principal) > MAX_ID_LEN or not _ID_RE.match(req.principal):
            return self._deny(req.request_id, "bad_identifier", "illegal chars/length")
        if req.action not in ALLOWED_ACTIONS:
            return self._deny(req.request_id, "action_not_allowed", req.action)
        if len(req.resource) > MAX_RESOURCE_LEN or "\x00" in req.resource:
            return self._deny(req.request_id, "bad_resource", "length/NUL")
        if ".." in req.resource.replace("\\", "/").split("/"):
            return self._deny(req.request_id, "path_traversal", req.resource)
        if self._payload_size(req.payload) > MAX_PAYLOAD_BYTES:
            return self._deny(req.request_id, "payload_too_large", "")
        # 2. abuse control
        if not self.limiter.allow(req.principal):
            return self._deny(req.request_id, "rate_limited", req.principal)
        # 3. authentication + authorization gate
        if not self.trust.authenticate(req.principal, req.credentials):
            return self._deny(req.request_id, "auth_failed", req.principal)
        if not self.trust.is_permitted(req):
            return self._deny(req.request_id, "not_permitted", f"{req.action}:{req.resource}")
        if self.audit:
            self.audit.record("barrier_allow", request_id=req.request_id)
        return LayerResult(self.name, Decision.ALLOW, reason="ok")
