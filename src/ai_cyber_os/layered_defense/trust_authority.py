"""Identity, permissions, revocation and second-party approvals."""
from __future__ import annotations
from typing import Dict, Optional, Set
from .contracts import AuditSink, Decision, Request
from .crypto_integrity import Integrity


class TrustAuthority:
    def __init__(self, integrity: Integrity, audit: Optional[AuditSink] = None) -> None:
        self._integrity, self._audit = integrity, audit
        self._roles: Dict[str, Set[str]] = {}
        self._revoked: Set[str] = set()
        self._suspended: Set[str] = set()
        self._approvals: Dict[str, str] = {}

    def _log(self, event: str, **fields) -> None:
        if self._audit:
            self._audit.record(event, **fields)

    def issue_token(self, principal: str) -> str:
        return f"{principal}.{self._integrity.sign(principal.encode())}"

    def authenticate(self, principal: str, token) -> bool:
        try:
            if not isinstance(token, str) or "." not in token:
                return False
            who, mac = token.rsplit(".", 1)
            ok = who == principal and self._integrity.verify(who.encode(), mac)
            ok = ok and principal not in self._revoked and principal not in self._suspended
        except Exception:
            ok = False
        self._log("auth", principal=principal, ok=ok)
        return ok

    def grant(self, principal: str, action: str, resource_prefix: str) -> None:
        self._roles.setdefault(principal, set()).add(f"{action}:{resource_prefix}")
        self._log("grant", principal=principal, action=action, prefix=resource_prefix)

    def revoke(self, principal: str) -> None:
        self._revoked.add(principal)
        self._log("revoke", principal=principal)

    def suspend(self, principal: str) -> None:
        self._suspended.add(principal)
        self._log("suspend", principal=principal)

    def reinstate(self, principal: str) -> None:
        self._suspended.discard(principal)
        self._log("reinstate", principal=principal)

    def is_permitted(self, request: Request) -> bool:
        if request.principal in self._revoked or request.principal in self._suspended:
            return False
        return any(
            perm.partition(":")[0] == request.action and request.resource.startswith(perm.partition(":")[2])
            for perm in self._roles.get(request.principal, ())
        )

    def approve(self, request_id: str, approver: str) -> None:
        self._approvals[request_id] = approver
        self._log("approve", request_id=request_id, approver=approver)

    def has_approval(self, request: Request) -> bool:
        approver = self._approvals.get(request.request_id)
        return bool(approver) and approver != request.principal

    def decide(self, request: Request) -> Decision:
        try:
            return Decision.ALLOW if self.authenticate(request.principal, request.credentials) and self.is_permitted(request) else Decision.BLOCK
        except Exception:
            return Decision.ERROR
