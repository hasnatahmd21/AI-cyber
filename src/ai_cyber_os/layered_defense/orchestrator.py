"""Canonical defence orchestration: barrier, isolation, independent layers 1-3."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Any, Optional
from .contracts import AuditSink, Decision, Finding, FinalResult, LayerResult, Request, is_authorized, most_severe


class Orchestrator:
    def __init__(self, barrier, layer1, layer2, layer3, isolation, deception, audit: Optional[AuditSink] = None, timeout_s: float = 2.0):
        self.barrier, self.l1, self.l2, self.l3 = barrier, layer1, layer2, layer3
        self.isolation, self.deception, self.audit, self.timeout = isolation, deception, audit, timeout_s
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ai-cyber-defence")

    def _audit(self, event: str, **fields: Any) -> None:
        if self.audit: self.audit.record(event, **fields)

    def _run_layer(self, layer, request, prior):
        name = getattr(layer, "name", "unknown")
        future = self._pool.submit(layer.evaluate, request, prior)
        try:
            result = future.result(timeout=self.timeout)
            if not isinstance(result, LayerResult): raise TypeError("invalid layer result")
            return result
        except FutureTimeout:
            future.cancel()
            return LayerResult(name, Decision.ERROR, (Finding(name, "timeout", 10),), "timeout")
        except Exception as exc:
            return LayerResult(name, Decision.ERROR, (Finding(name, "exception", 10, type(exc).__name__),), "exception")

    def _finish(self, request_id, results, trace, decision, reason):
        self._audit("decision", request_id=request_id, decision=decision.value, reason=reason, trace=list(trace))
        return FinalResult(request_id, decision, tuple(results), tuple(trace), reason)

    def handle(self, request: Any) -> FinalResult:
        request_id = getattr(request, "request_id", "?")
        results, trace = [], []
        barrier_result = self._run_layer(self.barrier, request, ())
        results.append(barrier_result); trace.append(f"barrier:{barrier_result.decision.value}")
        if barrier_result.decision is not Decision.ALLOW:
            decision = Decision.BLOCK if barrier_result.decision is not Decision.ERROR else Decision.ERROR
            return self._finish(request_id, results, trace, decision, f"barrier:{barrier_result.reason}")

        if self.isolation.is_quarantined(request.principal):
            trace.append("isolation:quarantined")
            if self.deception.is_decoy(request.resource): self.deception.serve(request)
            return self._finish(request_id, results, trace, Decision.QUARANTINE, "principal_quarantined")
        if self.deception.is_decoy(request.resource):
            self.isolation.quarantine(request.principal, "touched_decoy")
            trace.append("deception:decoy_touched")
            return self._finish(request_id, results, trace, Decision.QUARANTINE, "decoy_touched")

        for layer in (self.l1, self.l2, self.l3):
            result = self._run_layer(layer, request, tuple(results))
            results.append(result); trace.append(f"{result.layer}:{result.decision.value}")
            if result.decision is Decision.QUARANTINE:
                self.isolation.quarantine(request.principal, f"{result.layer}:{result.reason}")
                return self._finish(request_id, results, trace, Decision.QUARANTINE, result.reason)
            if not is_authorized(result.decision):
                return self._finish(request_id, results, trace, result.decision, f"{result.layer}:{result.reason}")
        final = most_severe(*(r.decision for r in results))
        return self._finish(request_id, results, trace, final, "ok" if final is Decision.ALLOW else "restricted")

    def shutdown(self):
        self._pool.shutdown(wait=False, cancel_futures=True)
