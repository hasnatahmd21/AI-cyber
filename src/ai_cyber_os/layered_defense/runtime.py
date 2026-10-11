"""Single wiring point for the layered defence components."""
from __future__ import annotations
import os, secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional
from .audit_telemetry import AuditLog
from .barrier import Barrier, RateLimiter
from .contracts import SecurityError
from .crypto_integrity import EnvKeyProvider, Integrity, KeyProvider, StaticKeyProvider
from .deception import Deception
from .isolation import Isolation
from .layer1 import Layer1
from .layer2 import Layer2
from .layer3 import Layer3
from .orchestrator import Orchestrator
from .trust_authority import TrustAuthority


class StartupError(SecurityError): pass


@dataclass
class System:
    orchestrator: Orchestrator
    audit: AuditLog
    trust: TrustAuthority
    isolation: Isolation
    deception: Deception

    def shutdown(self) -> None:
        self.orchestrator.shutdown()
        self.audit.record("shutdown")


def build_system(config: Optional[Dict[str, Any]] = None, key_provider: Optional[KeyProvider] = None) -> System:
    cfg = {"rate_capacity": 20, "rate_refill": 5.0, "timeout_s": 2.0, "strike_limit": 3,
           "releasers": [], "ephemeral_key": False, "it_tech_source": None}
    cfg.update(config or {})
    if key_provider is None:
        if cfg["ephemeral_key"]:
            key_provider = StaticKeyProvider({"default": secrets.token_bytes(32)})
        elif os.environ.get("AI_CYBER_KEY_DEFAULT"):
            key_provider = EnvKeyProvider()
        else:
            raise StartupError("signing key provider is required")
    try: key_provider.get_key("default")
    except Exception as exc: raise StartupError(f"invalid signing key: {exc}") from exc
    audit = AuditLog()
    trust = TrustAuthority(Integrity(key_provider), audit)
    isolation = Isolation(set(cfg["releasers"]), audit)
    deception = Deception(isolation, audit)
    barrier = Barrier(trust, RateLimiter(cfg["rate_capacity"], cfg["rate_refill"]), audit)
    orchestrator = Orchestrator(barrier, Layer1(), Layer2(trust, strike_limit=cfg["strike_limit"]),
                                Layer3(trust, it_tech_source=cfg["it_tech_source"]), isolation, deception, audit, cfg["timeout_s"])
    audit.record("startup", version="ai-cyber-layered-defence")
    return System(orchestrator, audit, trust, isolation, deception)
