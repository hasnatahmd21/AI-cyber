"""Canonical startup path: config loading, dependency wiring, lifecycle, entry-point inventory."""
from __future__ import annotations

import ast
import os
import secrets
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .audit_telemetry import AuditLog
from .barrier import Barrier, RateLimiter
from .contracts import SecurityError
from .crypto_integrity import EnvKeyProvider, Integrity, KeyProvider, StaticKeyProvider
from .deception import Deception
from .hydra import Hydra
from .isolation import Isolation
from .layer1 import Layer1
from .layer2 import Layer2
from .layer3 import Layer3
from .orchestrator import Orchestrator
from .trust_authority import TrustAuthority


class StartupError(SecurityError):
    pass


@dataclass
class System:
    orchestrator: Orchestrator
    audit: AuditLog
    trust: TrustAuthority
    isolation: Isolation
    deception: Deception
    hydra: Hydra

    def shutdown(self) -> None:
        self.orchestrator.shutdown()
        self.audit.record("shutdown")


def build_system(config: Optional[Dict[str, Any]] = None, key_provider: Optional[KeyProvider] = None) -> System:
    """Single wiring point. There is no 'test mode': tests use the same code with injected keys."""
    cfg = {"rate_capacity": 20, "rate_refill": 5.0, "timeout_s": 2.0, "strike_limit": 3,
           "releasers": [], "ephemeral_key": False}
    cfg.update(config or {})
    if key_provider is None:
        if cfg["ephemeral_key"]:
            key_provider = StaticKeyProvider({"default": secrets.token_bytes(32)})
        elif os.environ.get("AI_CYBER_KEY_DEFAULT"):
            key_provider = EnvKeyProvider()
        else:
            raise StartupError("no signing key: set AI_CYBER_KEY_DEFAULT (hex, >=16 bytes) "
                               "or pass ephemeral_key=True for demos")
    try:
        key_provider.get_key("default")
    except Exception as e:
        raise StartupError(f"key provider invalid: {e}") from e
    audit = AuditLog()
    trust = TrustAuthority(Integrity(key_provider), audit)
    iso = Isolation(set(cfg["releasers"]), audit)
    dec = Deception(iso, audit)
    barrier = Barrier(trust, RateLimiter(cfg["rate_capacity"], cfg["rate_refill"]), audit)
    orch = Orchestrator(barrier, Layer1(), Layer2(trust, strike_limit=cfg["strike_limit"]), Layer3(trust),
                        iso, dec, audit, cfg["timeout_s"])
    audit.record("startup", version="1.0.0")
    return System(orch, audit, trust, iso, dec, Hydra())


def find_entry_points(root: str) -> List[str]:
    """AST scan for `if __name__ == '__main__'` blocks (so strings in code aren't false positives)."""
    found = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in ("__pycache__", ".git")]
        for f in fn:
            if not f.endswith(".py"):
                continue
            p = os.path.join(dp, f)
            try:
                tree = ast.parse(open(p, encoding="utf-8").read())
            except SyntaxError:
                continue
            for n in tree.body:
                if (isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                        and isinstance(n.test.left, ast.Name) and n.test.left.id == "__name__"):
                    found.append(os.path.relpath(p, root).replace(os.sep, "/"))
                    break
    return sorted(found)
