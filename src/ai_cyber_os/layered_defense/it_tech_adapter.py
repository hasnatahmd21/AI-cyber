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
    """Persistent adapter around IT-Tech's real network-state and invariant engine.

    The topology is built once per runtime. Request observations are retained in a
    bounded rolling window, so the engine learns from recent activity without an
    unbounded in-memory signal list. Health checks recompute the existing state and
    never inject synthetic clean traffic.
    """

    _MAX_SIGNALS_PER_SOURCE = 128

    def __init__(self, source_path: str) -> None:
        self.module = _load_it_tech(source_path)
        self._lock = threading.RLock()
        self._sequence = 0
        self.engine = self.module.NetworkSecurityStateEngine()
        self._source_nodes = {
            "internal": "source-internal",
            "external": "source-public",
        }
        self._configure_topology()

    def _configure_topology(self) -> None:
        module = self.module
        engine = self.engine
        # The monolith reuses the global name Zone later in the file, shadowing
        # the network section's dataclass. NetworkTopology consumes this structural
        # contract, so keep the existing compatibility shim explicit.
        for zone_id, kind, ceiling in (
            ("public", module.ZoneKind.PUBLIC, 0.6),
            ("dmz", module.ZoneKind.DMZ, 0.8),
            ("internal", module.ZoneKind.INTERNAL, 1.0),
            ("data", module.ZoneKind.DATA, 1.0),
        ):
            engine.add_zone(SimpleNamespace(zone_id=zone_id, kind=kind, trust_ceiling=ceiling))

        engine.add_node(module.NetworkNode(
            self._source_nodes["internal"], module.NodeKind.DEVICE, "internal", 0.3
        ))
        engine.add_node(module.NetworkNode(
            self._source_nodes["external"], module.NodeKind.DEVICE, "public", 0.3
        ))
        engine.add_node(module.NetworkNode("gateway", module.NodeKind.CONTROL, "dmz", 0.5))
        engine.add_node(module.NetworkNode("hydra", module.NodeKind.SERVICE, "internal", 0.8))
        engine.add_node(module.NetworkNode("protected-data", module.NodeKind.DEVICE, "data", 0.95))

        secure_link = module.LinkSecurityState(
            encrypted=True, authenticated=True, integrity_protected=True,
            monitored=True, least_privilege=True,
        )
        engine.add_link(module.NetworkLink(
            "internal-to-hydra", self._source_nodes["internal"], "hydra",
            module.LinkKind.VIRTUAL, secure_link,
        ))
        engine.add_link(module.NetworkLink(
            "public-to-gateway", self._source_nodes["external"], "gateway",
            module.LinkKind.VIRTUAL, secure_link,
        ))
        engine.add_link(module.NetworkLink(
            "gateway-to-hydra", "gateway", "hydra", module.LinkKind.VIRTUAL, secure_link,
        ))
        # Protected data remains isolated; no application link enters this segment.
        engine.add_segment(module.NetworkSegment(
            "isolated-data", "data", module.SegmentEnforcement.ISOLATED,
            frozenset({"protected-data"}),
        ))
        engine.recompute(at=datetime.now(timezone.utc))

    @staticmethod
    def _request_source(request: Request) -> str:
        return "internal" if request.source == "internal" else "external"

    def _record_signal(self, request: Request, *, risk: float, source: str, now: datetime) -> Any:
        node_id = self._source_nodes[source]
        polarity = 1.0 - (2.0 * risk)
        if source == "external":
            # The public-zone ceiling is 0.6; never give a public source the
            # same positive trust signal as a source already inside the boundary.
            polarity = min(polarity, 0.2)

        # This is the actual IT-Tech engine's internal rolling signal collection.
        # Pin the adapter to this exact contract: if a future monolith revision
        # changes it, fail closed rather than silently losing bounded-state safety.
        signals = getattr(self.engine, "_signals", None)
        if not isinstance(signals, dict):
            raise RuntimeError("IT-Tech network signal store API changed")
        node_signals = signals.setdefault(node_id, [])
        if not isinstance(node_signals, list):
            raise RuntimeError("IT-Tech network signal bucket API changed")
        if len(node_signals) >= self._MAX_SIGNALS_PER_SOURCE:
            del node_signals[: len(node_signals) - self._MAX_SIGNALS_PER_SOURCE + 1]

        self._sequence += 1
        suffix = f"{self._sequence:016x}"
        evidence = SimpleNamespace(
            evidence_id=f"ai-cyber-evidence-{suffix}",
            source="ai-cyber-layer2",
            confidence=1.0,
            observed_at=now,
            payload={
                "network_risk": risk,
                "request_source": source,
                "principal_digest": __import__("hashlib").sha256(
                    str(request.principal).encode("utf-8", "replace")
                ).hexdigest()[:16],
            },
        )
        self.engine.observe_signal(node_id, self.module.NetworkTrustSignal(
            signal_id=f"ai-cyber-signal-{suffix}",
            weight=1.0,
            polarity=polarity,
            at=now,
            evidence=evidence,
        ))
        return node_id

    def _recompute_locked(self, at: datetime) -> tuple[bool, str, dict[str, str]]:
        self.engine.recompute(at=at)
        labels: dict[str, str] = {}
        bad_labels = {
            self.module.NetworkLabel.SUSPICIOUS,
            self.module.NetworkLabel.COMPROMISED,
            self.module.NetworkLabel.QUARANTINED,
        }
        for source_name, node_id in self._source_nodes.items():
            state = self.engine.current_state(node_id)
            if state is None:
                return False, f"IT-Tech network engine produced no {source_name} source state", labels
            label = state.label
            labels[source_name] = getattr(label, "value", str(label))
            if label in bad_labels:
                return False, f"IT-Tech network trust is {labels[source_name]}", labels

        critical = [
            violation for violation in self.engine.violations()
            if getattr(violation.severity, "value", str(violation.severity)).lower()
            in {"critical", "high"}
        ]
        if critical:
            ids = ",".join(str(v.invariant_id) for v in critical)
            return False, "IT-Tech network invariant violation: " + ids, labels
        return True, "network state recomputed; invariants clean", labels

    def evaluate(self, request: Request) -> tuple[bool, str]:
        try:
            attrs: Any = request.attributes
            if not hasattr(attrs, "get"):
                return False, "invalid network telemetry shape"
            source = self._request_source(request)
            default_risk = 0.0 if source == "internal" else 0.2
            risk = attrs.get("network_risk", default_risk)
            if (
                isinstance(risk, bool)
                or not isinstance(risk, (int, float))
                or not math.isfinite(risk)
                or not 0.0 <= risk <= 1.0
            ):
                return False, "invalid network risk telemetry"

            now = datetime.now(timezone.utc)
            with self._lock:
                self._record_signal(request, risk=float(risk), source=source, now=now)
                allowed, rationale, labels = self._recompute_locked(now)
                # This direct threshold is intentionally independent of the
                # trust label's confidence threshold: a single high-risk request
                # is rejected immediately, even before enough evidence accumulates.
                if float(risk) >= 0.7:
                    return False, "IT-Tech network risk threshold exceeded"
                if not allowed:
                    return False, rationale
                label = labels[source]
                return True, f"network state {label}; invariants clean"
        except Exception as exc:
            return False, f"IT-Tech network engine failed closed: {type(exc).__name__}: {exc!r}"

    def health_check(self) -> tuple[bool, str]:
        """Recompute observed network state without fabricating fresh telemetry."""
        try:
            with self._lock:
                allowed, reason, labels = self._recompute_locked(datetime.now(timezone.utc))
                if not allowed:
                    return False, reason
                return True, "IT-Tech network engine active; " + ", ".join(
                    f"{source}={label}" for source, label in sorted(labels.items())
                )
        except Exception as exc:
            return False, f"IT-Tech network health check failed closed: {type(exc).__name__}: {exc!r}"

    def snapshot(self) -> dict[str, Any]:
        """Return bounded, non-secret network-state diagnostics for live status."""
        try:
            with self._lock:
                states = {}
                for source, node_id in self._source_nodes.items():
                    state = self.engine.current_state(node_id)
                    if state is not None:
                        states[source] = {
                            "label": getattr(state.label, "value", str(state.label)),
                            "trust_score": float(state.trust_score),
                            "trust_confidence": float(state.trust_confidence),
                        }
                signals = getattr(self.engine, "_signals", {})
                return {
                    "active": True,
                    "engine": "IT-Tech NetworkSecurityStateEngine",
                    "observations": sum(len(v) for v in signals.values() if isinstance(v, list)),
                    "observation_limit_per_source": self._MAX_SIGNALS_PER_SOURCE,
                    "states": states,
                }
        except Exception as exc:
            return {"active": False, "error": f"{type(exc).__name__}: {exc}"}
