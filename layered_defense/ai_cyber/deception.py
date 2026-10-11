"""Defensive deception: synthetic decoys only, served exclusively to quarantined principals.
Decoys never contain or derive from real data."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from .contracts import AuditSink, Request, SecurityError
from .isolation import Isolation


class DeceptionError(SecurityError):
    pass


class Deception:
    PREFIX = "/decoy/"

    def __init__(self, isolation: Isolation, audit: Optional[AuditSink] = None) -> None:
        self._iso, self._audit = isolation, audit
        self._decoys: Dict[str, str] = {}
        self.interactions: List[Dict[str, Any]] = []

    def register_decoy(self, name: str) -> str:
        path = self.PREFIX + name.strip("/")
        # synthetic content derived only from the decoy name (never real data)
        self._decoys[path] = "DECOY:" + hashlib.sha256(path.encode()).hexdigest()[:16]
        return path

    def is_decoy(self, resource: str) -> bool:
        return resource in self._decoys

    def serve(self, req: Request) -> str:
        if not self._iso.is_quarantined(req.principal):
            raise DeceptionError("decoys are served only inside an authorized isolated environment")
        if req.resource not in self._decoys:
            raise DeceptionError("not a decoy resource")
        rec = {"principal": req.principal, "resource": req.resource, "action": req.action,
               "request_id": req.request_id}
        self.interactions.append(rec)
        if self._audit:
            self._audit.record("decoy_interaction", **rec)
        return self._decoys[req.resource]
