"""Layer 3: strongest fail-closed verification for critical actions."""
from __future__ import annotations
from typing import Iterable, Tuple
from .contracts import Decision, Finding, LayerResult, Request, Sensitivity
from .trust_authority import TrustAuthority
from .it_tech_adapter import ITTechAuthorityGate

_CRITICAL = frozenset({"delete", "execute", "run"})


class Layer3:
    name = "layer3"
    def __init__(self, trust: TrustAuthority, critical_prefixes: Iterable[str] = ("/system", "/keys", "/audit"),
                 it_tech_source: str | None = None):
        self.trust, self.critical_prefixes = trust, tuple(critical_prefixes)
        self.it_tech_gate = ITTechAuthorityGate(it_tech_source) if it_tech_source else None

    def evaluate(self, req: Request, prior: Tuple[LayerResult, ...] = ()) -> LayerResult:
        try:
            critical = req.sensitivity is Sensitivity.CRITICAL or req.action in _CRITICAL or req.resource.startswith(self.critical_prefixes)
            if self.trust.decide(req) is not Decision.ALLOW:
                return LayerResult(self.name, Decision.BLOCK, (Finding(self.name, "unauthorized", 10),), "unauthorized")
            if self.it_tech_gate is not None and req.resource.startswith("hydra:"):
                it_allowed, rationale = self.it_tech_gate.authorize(req)
                if not it_allowed:
                    return LayerResult(
                        self.name, Decision.BLOCK,
                        (Finding(self.name, "it_tech_authority_denied", 10, rationale),),
                        "it_tech_authority_denied",
                    )
            if not critical: return LayerResult(self.name, Decision.ALLOW, reason="non_critical")
            if not self.trust.has_approval(req):
                return LayerResult(self.name, Decision.ESCALATE, (Finding(self.name, "approval_required", 8),), "critical_needs_approval")
            if any(r.layer == "layer2" and r.decision is not Decision.ALLOW for r in prior):
                return LayerResult(self.name, Decision.BLOCK, (Finding(self.name, "upstream_concern", 9),), "upstream_concern")
            return LayerResult(self.name, Decision.ALLOW, reason="critical_verified")
        except Exception as exc:
            return LayerResult(self.name, Decision.BLOCK, (Finding(self.name, "internal_error", 10, type(exc).__name__),), "fail_closed")
