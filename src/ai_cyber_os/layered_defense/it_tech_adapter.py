"""Adapter that wires the existing IT-Tech authority engine into the runtime's strongest layer.

The monolith is loaded only after the startup integrity gate verifies its signed file
baseline. The adapter does not execute the file as a script and never trusts unknown
posture labels or malformed risk values.
"""
from __future__ import annotations

import importlib.util
import math
import os
import sys
import threading
from datetime import datetime, timezone
from types import ModuleType
from typing import Any

from .contracts import Request


_MODULE_LOCK = threading.RLock()
_MODULES: dict[str, ModuleType] = {}


def _load_it_tech(source_path: str) -> ModuleType:
    path = os.path.realpath(source_path)
    with _MODULE_LOCK:
        cached = _MODULES.get(path)
        if cached is not None:
            return cached
        module_name = "ai_cyber_os._trusted_it_tech_runtime"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError("IT-Tech source cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(module_name, None)
            raise
        required = ("AuthorityEngine", "Principal", "PrincipalKind", "AuthorityDecisionKind",
                    "SecurityPosture", "AuthorizationRequest", "PolicyRule")
        if any(not hasattr(module, name) for name in required):
            sys.modules.pop(module_name, None)
            raise RuntimeError("IT-Tech authority API is incomplete")
        _MODULES[path] = module
        return module


class ITTechAuthorityGate:
    """Use the existing IT-Tech AuthorityEngine as an independent authorization layer."""

    def __init__(self, source_path: str, principal_id: str = "hydra-runtime") -> None:
        self.module = _load_it_tech(source_path)
        self.principal_id = principal_id
        self.engine = self.module.AuthorityEngine()
        now = datetime.now(timezone.utc)
        principal = self.module.Principal(
            principal_id=principal_id,
            kind=self.module.PrincipalKind.SERVICE,
            tenant_id="ai-cyber",
        )
        self.engine.register_principal(principal)
        self.engine.grant_root(
            principal_id=principal_id,
            capabilities={"execute:hydra"},
            targets={"hydra:run"},
            issued_at=now,
        )
        self.engine.add_policy(self.module.PolicyRule(
            rule_id="deny-suspicious-or-worse",
            decision=self.module.AuthorityDecisionKind.DENY,
            posture_trigger="suspicious",
        ))
        self.engine.add_policy(self.module.PolicyRule(
            rule_id="deny-high-risk",
            decision=self.module.AuthorityDecisionKind.DENY,
            min_risk=0.7,
        ))

    def authorize(self, request: Request) -> tuple[bool, str]:
        try:
            attributes: Any = request.attributes
            label = attributes.get("it_tech_posture", "trusted")
            risk = attributes.get("it_tech_risk", 0.0)
            confidence = attributes.get("it_tech_confidence", 1.0)
            if label not in {"unknown", "observed", "trusted", "degraded", "suspicious", "compromised", "quarantined"}:
                return False, "invalid IT-Tech posture"
            if isinstance(risk, bool) or not isinstance(risk, (int, float)) or not math.isfinite(risk) or not 0.0 <= risk <= 1.0:
                return False, "invalid IT-Tech risk"
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
                return False, "invalid IT-Tech confidence"
            now = datetime.now(timezone.utc)
            posture = self.module.SecurityPosture(label=label, risk=float(risk), confidence=float(confidence))
            decision = self.engine.authorize(self.module.AuthorizationRequest(
                request_id=request.request_id,
                principal_id=self.principal_id,
                capability="execute:hydra",
                target="hydra:run",
                intent="run HYDRA behind the verified layered defence",
                at=now,
                security_posture=posture,
                context={"action": request.action, "resource": request.resource},
            ))
            allowed = decision.kind is self.module.AuthorityDecisionKind.ALLOW
            return allowed, decision.rationale
        except Exception as exc:
            return False, f"IT-Tech authority failed closed: {type(exc).__name__}"
