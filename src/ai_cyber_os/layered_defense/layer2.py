"""Layer 2: independent detection, policy recheck and strike correlation."""
from __future__ import annotations
import re, time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple
from .contracts import Decision, Finding, LayerResult, Request
from .trust_authority import TrustAuthority

_INDEPENDENT = (
    ("sql_keyword_chain", re.compile(r"(select\s.+\sfrom\s|insert\s+into\s|drop\s+(table|database)|xp_cmdshell)", re.I), 8),
    ("html_active", re.compile(r"<\s*(script|iframe|object)|srcdoc\s*=|data:text/html", re.I), 7),
    ("cmd_chain", re.compile(r"(\|\s*(sh|bash)\b|\x60[^\x60]+\x60|\$\{IFS\}|/etc/passwd|/bin/(sh|bash))", re.I), 9),
    ("encoded_traversal", re.compile(r"(%2e|%252e|\.\.[/\\])", re.I), 7),
)


class Layer2:
    name = "layer2"
    def __init__(self, trust: TrustAuthority, window_s: float = 60.0, strike_limit: int = 3, clock=time.monotonic):
        self.trust, self.window, self.limit, self._clock = trust, window_s, strike_limit, clock
        self._strikes: Dict[str, Deque[float]] = defaultdict(deque)

    def evaluate(self, req: Request, prior: Tuple[LayerResult, ...] = ()) -> LayerResult:
        text = (str(req.payload) if req.payload is not None else "") + " " + req.resource
        findings = [Finding(self.name, code, sev) for code, rx, sev in _INDEPENDENT if rx.search(text)]
        if self.trust.decide(req) is not Decision.ALLOW:
            findings.append(Finding(self.name, "policy_denied", 9))
        l1 = next((r for r in prior if r.layer == "layer1"), None)
        if l1 is None: findings.append(Finding(self.name, "layer1_missing", 6))
        elif l1.decision in (Decision.ALLOW, Decision.RESTRICT) and any(f.severity >= 7 for f in findings):
            findings.append(Finding(self.name, "layer1_bypass_suspected", 9))
        now = self._clock(); q = self._strikes[req.principal]
        while q and now - q[0] > self.window: q.popleft()
        if any(f.severity >= 7 for f in findings): q.append(now)
        if len(q) >= self.limit: findings.append(Finding(self.name, "repeated_suspicious_behaviour", 9))
        worst = max((f.severity for f in findings), default=0)
        if len(q) >= self.limit: decision = Decision.QUARANTINE
        elif worst >= 6: decision = Decision.BLOCK if worst >= 7 else Decision.ESCALATE
        else: decision = Decision.ALLOW
        return LayerResult(self.name, decision, tuple(findings), "independent_check")
