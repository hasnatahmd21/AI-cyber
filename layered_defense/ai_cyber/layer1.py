"""Layer 1 - primary containment: threat detection + least-privilege (RESTRICT)."""
from __future__ import annotations

import re
from typing import Any, List, Tuple

from .contracts import Decision, Finding, LayerResult, Request

PATTERNS = (
    ("sqli", re.compile(r"(\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1|;\s*drop\s+table|--\s*$)", re.I), 8),
    ("script_injection", re.compile(r"<\s*script\b|javascript:|onerror\s*=", re.I), 7),
    ("shell_injection", re.compile(r"(;|\|\||&&|\$\()\s*(rm|curl|wget|nc|bash|sh)\b", re.I), 9),
    ("path_traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.I), 7),
)
MAX_SOFT_PAYLOAD = 100_000


def payload_text(p: Any) -> str:
    if p is None:
        return ""
    if isinstance(p, (bytes, bytearray)):
        return bytes(p).decode("utf-8", "replace")
    return str(p)


class Layer1:
    name = "layer1"

    def evaluate(self, req: Request, prior: Tuple[LayerResult, ...] = ()) -> LayerResult:
        text = payload_text(req.payload) + " " + req.resource
        findings: List[Finding] = []
        for code, rx, sev in PATTERNS:
            if rx.search(text):
                findings.append(Finding(self.name, code, sev, "pattern match"))
        if len(text) > MAX_SOFT_PAYLOAD:
            findings.append(Finding(self.name, "large_payload", 3))
        worst = max((f.severity for f in findings), default=0)
        if worst >= 7:
            return LayerResult(self.name, Decision.BLOCK, tuple(findings), "threat_detected")
        if worst > 0 or req.source != "internal" and req.action in ("delete", "execute"):
            # least-privilege: processed with reduced privileges
            return LayerResult(self.name, Decision.RESTRICT, tuple(findings), "restricted")
        return LayerResult(self.name, Decision.ALLOW, tuple(findings), "clean")
