"""Layer 3 - strongest defence: critical-action verification, fail-closed."""
from __future__ import annotations

from typing import Iterable, Tuple

from .contracts import Decision, Finding, LayerResult, Request, Sensitivity
from .trust_authority import TrustAuthority

CRITICAL_ACTIONS = frozenset({"delete", "execute"})


class Layer3:
    name = "layer3"

    def __init__(self, trust: TrustAuthority, critical_prefixes: Iterable[str] = ("/system", "/keys", "/audit")) -> None:
        self.trust = trust
        self.critical_prefixes = tuple(critical_prefixes)

    def is_critical(self, req: Request) -> bool:
        return (req.sensitivity is Sensitivity.CRITICAL or req.action in CRITICAL_ACTIONS
                or req.resource.startswith(self.critical_prefixes))

    def evaluate(self, req: Request, prior: Tuple[LayerResult, ...] = ()) -> LayerResult:
        try:
            if not self.is_critical(req):
                # still independently verifies authorization (no blind trust of earlier layers)
                if self.trust.decide(req) is not Decision.ALLOW:
                    return LayerResult(self.name, Decision.BLOCK, (Finding(self.name, "unauthorized", 9),), "unauthorized")
                return LayerResult(self.name, Decision.ALLOW, (), "non_critical")
            findings = []
            if self.trust.decide(req) is not Decision.ALLOW:
                findings.append(Finding(self.name, "unauthorized", 10))
            if not self.trust.has_approval(req):
                findings.append(Finding(self.name, "approval_required", 8, "critical op needs 2nd-party approval"))
            if any(r.decision is not Decision.ALLOW and r.layer != "layer1" for r in prior if r.layer in ("layer2",)):
                findings.append(Finding(self.name, "upstream_concern", 8))
            if findings:
                has_unauth = any(f.code == "unauthorized" for f in findings)
                d = Decision.BLOCK if has_unauth else Decision.ESCALATE
                return LayerResult(self.name, d, tuple(findings), "critical_denied")
            return LayerResult(self.name, Decision.ALLOW, (), "critical_verified")
        except Exception as e:  # fail closed
            return LayerResult(self.name, Decision.BLOCK, (Finding(self.name, "internal_error", 10, type(e).__name__),), "fail_closed")
