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
           "releasers": [], "ephemeral_key": False, "it_tech_source": None,
           "it_tech_integrity_verified": False}
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

    # The canonical application runtime must never come up with the IT-Tech
    # authority/network layers silently omitted or operating on unverified code.
    source = cfg.get("it_tech_source")
    integrity_verified = cfg.get("it_tech_integrity_verified")
    if not isinstance(integrity_verified, bool):
        raise StartupError("IT-Tech integrity verification must be an explicit boolean result")
    if not isinstance(source, str) or not source.strip():
        raise StartupError("verified IT-Tech source is required; defensive layers cannot be disabled")
    source = os.path.abspath(source)
    if os.path.islink(source) or not os.path.isfile(source):
        raise StartupError("IT-Tech source must be a regular, non-symlink file")
    if integrity_verified is not True:
        raise StartupError("signed IT-Tech source integrity verification is required before startup")
    cfg["it_tech_source"] = source

    audit = AuditLog()
    trust = TrustAuthority(Integrity(key_provider), audit)
    isolation = Isolation(set(cfg["releasers"]), audit)
    deception = Deception(isolation, audit)
    barrier = Barrier(trust, RateLimiter(cfg["rate_capacity"], cfg["rate_refill"]), audit)
    orchestrator = Orchestrator(
        barrier,
        Layer1(),
        Layer2(
            trust,
            strike_limit=cfg["strike_limit"],
            it_tech_source=cfg["it_tech_source"],
            it_tech_integrity_verified=cfg["it_tech_integrity_verified"],
        ),
        Layer3(
            trust,
            it_tech_source=cfg["it_tech_source"],
            it_tech_integrity_verified=cfg["it_tech_integrity_verified"],
        ),
        isolation,
        deception,
        audit,
        cfg["timeout_s"],
    )
    audit.record("startup", version="ai-cyber-layered-defence")
    return System(orchestrator, audit, trust, isolation, deception)
