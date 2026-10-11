"""Turn a verified dataset into extra detection rules for Layer 1.

Normalized 'rule pack' (what per-dataset converters - KEV, Sigma, Suricata... - must emit):
    {"rules": [{"code": "kev_xyz", "regex": "...", "severity": 7}, ...]}
Rules can only ADD findings; they can never relax what the built-in Layer 1 decided."""
from __future__ import annotations

import re
from typing import List, Tuple

from ..contracts import Decision, Finding, LayerResult, Request
from ..layer1 import Layer1, payload_text
from .dataset_loader import DatasetIntegrityError, VerifiedDataset

MAX_RULES = 5000
MAX_REGEX_LEN = 300
_NESTED_QUANT = re.compile(r"\([^)]*[+*][^)]*\)[+*{]")     # crude ReDoS guard


def compile_rules(ds: VerifiedDataset, rel: str = "rules.json") -> List[Tuple[str, "re.Pattern", int]]:
    data = ds.read_json(rel)
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise DatasetIntegrityError("rule pack malformed or too large")
    out = []
    for r in rules:
        try:
            code, rx, sev = str(r["code"]), str(r["regex"]), int(r["severity"])
        except Exception as e:
            raise DatasetIntegrityError("rule malformed") from e
        if not (0 <= sev <= 10) or len(rx) > MAX_REGEX_LEN or _NESTED_QUANT.search(rx):
            raise DatasetIntegrityError(f"rule rejected: {code}")
        try:
            out.append((code, re.compile(rx, re.I), sev))
        except re.error as e:
            raise DatasetIntegrityError(f"bad regex in rule {code}") from e
    return out


class DatasetLayer1(Layer1):
    """Built-in Layer 1 + dataset rules. Keeps name 'layer1' so Layer 2 bypass detection still works."""

    def __init__(self, extra_rules) -> None:
        self._extra = list(extra_rules)

    def evaluate(self, req: Request, prior: Tuple[LayerResult, ...] = ()) -> LayerResult:
        base = super().evaluate(req, prior)
        text = payload_text(req.payload) + " " + req.resource
        extra = tuple(Finding(self.name, c, s, "dataset rule") for c, rx, s in self._extra if rx.search(text))
        if not extra:
            return base
        findings = base.findings + extra
        worst = max(f.severity for f in findings)
        if worst >= 7 or base.decision is Decision.BLOCK:
            return LayerResult(self.name, Decision.BLOCK, findings, "threat_detected")
        if base.decision is Decision.ALLOW:
            return LayerResult(self.name, Decision.RESTRICT, findings, "restricted")
        return LayerResult(self.name, base.decision, findings, base.reason)
