"""Layer 2 - independent defence. Does NOT trust Layer 1's pass: it re-runs its own checks,
re-evaluates policy through the TrustAuthority, correlates behaviour and detects L1 bypass."""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Tuple

from .contracts import Decision, Finding, LayerResult, Request, most_severe
from .trust_authority import TrustAuthority

# Intentionally a separate rule set from layer1 (diverse detection, different regexes)
_INDEP = (
    ("sql_keyword_chain", re.compile(r"(select\s.+\sfrom\s|insert\s+into\s|drop\s+(table|database)|xp_cmdshell)", re.I), 8),
    ("html_active", re.compile(r"<\s*(script|iframe|object)|srcdoc\s*=|data:text/html", re.I), 7),
    ("cmd_chain", re.compile(r"(\|\s*(sh|bash)\b|`[^`]+`|\$\{IFS\}|/etc/passwd|/bin/(sh|bash))", re.I), 9),
    ("encoded_traversal", re.compile(r"(%2e|%252e|\.\.[/\\])", re.I), 7),
)


class Layer2:
    name = "layer2"

    def __init__(self, trust: TrustAuthority, window_s: float = 60.0, strike_limit: int = 3,
                 clock=time.monotonic) -> None:
        self.trust, self.window, self.limit, self._clock = trust, window_s, strike_limit, clock
        self._strikes: Dict[str, Deque[float]] = defaultdict(deque)

    def _correlate(self, principal: str, hit: bool) -> int:
        now = self._clock()
        q = self._strikes[principal]
        while q and now - q[0] > self.window:
            q.popleft()
        if hit:
            q.append(now)
        return len(q)

    def evaluate(self, req: Request, prior: Tuple[LayerResult, ...] = ()) -> LayerResult:
        findings = []
        text = (str(req.payload) if req.payload is not None else "") + " " + req.resource
        for code, rx, sev in _INDEP:
            if rx.search(text):
                findings.append(Finding(self.name, code, sev))
        # independent policy re-evaluation (never relies on barrier result)
        if self.trust.decide(req) is not Decision.ALLOW:
            findings.append(Finding(self.name, "policy_denied", 9, "independent policy check"))
        # bypass detection: an upstream layer allowed something we consider a threat
        l1 = next((r for r in prior if r.layer == "layer1"), None)
        if l1 is None:
            findings.append(Finding(self.name, "layer1_missing", 6, "no layer1 result"))
        elif l1.decision in (Decision.ALLOW, Decision.RESTRICT) and any(f.severity >= 7 for f in findings):
            findings.append(Finding(self.name, "layer1_bypass_suspected", 9))
        strikes = self._correlate(req.principal, any(f.severity >= 7 for f in findings))
        if strikes >= self.limit:
            findings.append(Finding(self.name, "repeated_suspicious_behaviour", 9, f"{strikes} strikes"))
        worst = max((f.severity for f in findings), default=0)
        if strikes >= self.limit:
            d = Decision.QUARANTINE
        elif worst >= 9 or any(f.code == "policy_denied" for f in findings):
            d = Decision.BLOCK
        elif worst >= 7:
            d = Decision.BLOCK
        elif worst >= 6:
            d = Decision.ESCALATE
        else:
            d = Decision.ALLOW
        return LayerResult(self.name, d, tuple(findings), "independent_check")
