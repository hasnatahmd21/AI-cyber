"""Central coordinator. Order: barrier -> isolation/decoy gate -> layer1 -> layer2 -> layer3.
Timeouts and exceptions yield ERROR (never an allow). Every decision is traced and audited."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
from typing import Any, Optional, Tuple

from .contracts import (AuditSink, Decision, Finding, FinalResult, LayerResult, Request,
                        is_authorized, most_severe)


class Orchestrator:
    def __init__(self, barrier, layer1, layer2, layer3, isolation, deception,
                 audit: Optional[AuditSink] = None, timeout_s: float = 2.0) -> None:
        self.barrier, self.l1, self.l2, self.l3 = barrier, layer1, layer2, layer3
        self.isolation, self.deception, self.audit, self.timeout = isolation, deception, audit, timeout_s
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="aicyber")

    def _run(self, layer, req, prior) -> LayerResult:
        name = getattr(layer, "name", "unknown")
        fut = self._pool.submit(layer.evaluate, req, prior)
        try:
            res = fut.result(timeout=self.timeout)
            if not isinstance(res, LayerResult):
                raise TypeError("layer returned invalid result")
            return res
        except FutTimeout:
            fut.cancel()
            return LayerResult(name, Decision.ERROR, (Finding(name, "timeout", 9),), "timeout")
        except Exception as e:
            return LayerResult(name, Decision.ERROR, (Finding(name, "exception", 9, type(e).__name__),), "exception")

    def _audit(self, event: str, **f: Any) -> None:
        if self.audit:
            self.audit.record(event, **f)

    def _final(self, req_id: str, results, trace, decision: Decision, reason: str) -> FinalResult:
        self._audit("decision", request_id=req_id, decision=decision.value, reason=reason, trace=list(trace))
        return FinalResult(req_id, decision, tuple(results), tuple(trace), reason)

    def handle(self, req: Any) -> FinalResult:
        rid = getattr(req, "request_id", "?") if isinstance(getattr(req, "request_id", None), str) else "?"
        results: list = []
        trace: list = []

        # [1] barrier - always first
        r = self._run(self.barrier, req, ())
        results.append(r); trace.append(f"barrier:{r.decision.value}")
        if r.decision is not Decision.ALLOW:
            d = r.decision if r.decision is Decision.ERROR else Decision.BLOCK
            return self._final(rid, results, trace, d, f"barrier:{r.reason}")

        # [7] isolation gate - quarantined principals only ever see decoys
        if self.isolation.is_quarantined(req.principal):
            trace.append("isolation:quarantined")
            if self.deception.is_decoy(req.resource):
                self.deception.serve(req)
                return self._final(rid, results, trace, Decision.QUARANTINE, "served_decoy")
            return self._final(rid, results, trace, Decision.QUARANTINE, "principal_quarantined")
        if self.deception.is_decoy(req.resource):   # honeytoken touched by a non-quarantined principal
            self.isolation.quarantine(req.principal, "touched_decoy")
            trace.append("deception:decoy_touched")
            return self._final(rid, results, trace, Decision.QUARANTINE, "decoy_touched")

        # [2][3][4] defence layers
        for layer in (self.l1, self.l2, self.l3):
            r = self._run(layer, req, tuple(results))
            results.append(r); trace.append(f"{r.layer}:{r.decision.value}")
            if r.decision is Decision.QUARANTINE:
                self.isolation.quarantine(req.principal, f"{r.layer}:{r.reason}")
                return self._final(rid, results, trace, Decision.QUARANTINE, f"{r.layer}:{r.reason}")
            if not is_authorized(r.decision):
                return self._final(rid, results, trace, r.decision, f"{r.layer}:{r.reason}")

        final = most_severe(*(x.decision for x in results))
        return self._final(rid, results, trace, final, "ok" if final is Decision.ALLOW else "restricted")

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
