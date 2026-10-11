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
from types import ModuleType, SimpleNamespace
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
                    "SecurityPosture", "AuthorizationRequest")
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
            if label in {"unknown", "suspicious", "compromised", "quarantined"}:
                return False, f"IT-Tech posture '{label}' does not authorize HYDRA"
            if float(risk) >= 0.7:
                return False, "IT-Tech risk threshold exceeded"
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


class ITTechNetworkGate:
    """Run the existing IT-Tech network-state engine and enforce its invariants."""

    def __init__(self, source_path: str) -> None:
        self.module = _load_it_tech(source_path)

    def evaluate(self, request: Request) -> tuple[bool, str]:
        try:
            module = self.module
            attrs: Any = request.attributes
            default_risk = 0.0 if request.source == "internal" else 0.2
            risk = attrs.get("network_risk", default_risk)
            if isinstance(risk, bool) or not isinstance(risk, (int, float)) or not math.isfinite(risk) or not 0.0 <= risk <= 1.0:
                return False, "invalid network risk telemetry"

            if float(risk) >= 0.7:
                return False, "IT-Tech network risk threshold exceeded"

            now = datetime.now(timezone.utc)
            engine = module.NetworkSecurityStateEngine()
            # The legacy IT-Tech monolith reuses the global name Zone in a
            # later section. Its final binding is an enum, shadowing the network
            # engine's original dataclass. Supply the structural contract expected
            # by NetworkTopology instead of instantiating the shadowed enum.
            for zone_id, kind, ceiling in (
                ("public", module.ZoneKind.PUBLIC, 0.6),
                ("dmz", module.ZoneKind.DMZ, 0.8),
                ("internal", module.ZoneKind.INTERNAL, 1.0),
                ("data", module.ZoneKind.DATA, 1.0),
            ):
                engine.add_zone(SimpleNamespace(zone_id=zone_id, kind=kind, trust_ceiling=ceiling))

            source_is_internal = request.source == "internal"
            source_zone = "internal" if source_is_internal else "public"
            engine.add_node(module.NetworkNode("source", module.NodeKind.DEVICE, source_zone, 0.3))
            engine.add_node(module.NetworkNode("gateway", module.NodeKind.CONTROL, "dmz", 0.5))
            engine.add_node(module.NetworkNode("hydra", module.NodeKind.SERVICE, "internal", 0.8))
            engine.add_node(module.NetworkNode("protected-data", module.NodeKind.DEVICE, "data", 0.95))

            secure_link = module.LinkSecurityState(
                encrypted=True, authenticated=True, integrity_protected=True,
                monitored=True, least_privilege=True,
            )
            if source_is_internal:
                engine.add_link(module.NetworkLink("source-to-hydra", "source", "hydra", module.LinkKind.VIRTUAL, secure_link))
            else:
                engine.add_link(module.NetworkLink("source-to-gateway", "source", "gateway", module.LinkKind.VIRTUAL, secure_link))
                engine.add_link(module.NetworkLink("gateway-to-hydra", "gateway", "hydra", module.LinkKind.VIRTUAL, secure_link))

            # The protected data segment is intentionally air-gapped in the model.
            engine.add_segment(module.NetworkSegment(
                "isolated-data", "data", module.SegmentEnforcement.ISOLATED,
                frozenset({"protected-data"}),
            ))
            polarity = 1.0 - (2.0 * float(risk))
            if not source_is_internal:
                polarity = min(polarity, 0.2)  # public-zone trust ceiling is 0.6
            # Evidence is also redeclared by later legacy sections; the final
            # module binding has an unrelated verification-evidence schema.
            evidence = SimpleNamespace(
                evidence_id=f"evidence-{request.request_id}",
                source="ai-cyber-layer2",
                confidence=1.0,
                observed_at=now,
                payload={"network_risk": float(risk), "request_source": request.source},
            )
            engine.observe_signal("source", module.NetworkTrustSignal(
                signal_id=f"signal-{request.request_id}",
                weight=1.0,
                polarity=polarity,
                at=now,
                evidence=evidence,
            ))
            engine.recompute(at=now)
            state = engine.current_state("source")
            if state is None:
                return False, "IT-Tech network engine produced no source state"
            if state.label in {
                module.NetworkLabel.SUSPICIOUS,
                module.NetworkLabel.COMPROMISED,
                module.NetworkLabel.QUARANTINED,
            }:
                return False, f"IT-Tech network trust is {state.label.value}"
            critical = [
                v for v in engine.violations()
                if getattr(v.severity, "value", str(v.severity)).lower() in {"critical", "high"}
            ]
            if critical:
                return False, "IT-Tech network invariant violation: " + ",".join(v.invariant_id for v in critical)
            return True, f"network state {state.label.value}; invariants clean"
        except Exception as exc:
            return False, f"IT-Tech network engine failed closed: {type(exc).__name__}: {exc!r}"
