"""Identity, permissions, revocation/suspension, approvals. Every decision is audited."""
from __future__ import annotations

from typing import Dict, Optional, Set

from .contracts import AuditSink, Decision, Request
from .crypto_integrity import Integrity


class TrustAuthority:
    def __init__(self, integrity: Integrity, audit: Optional[AuditSink] = None) -> None:
        self._int = integrity
        self._audit = audit
        self._roles: Dict[str, Set[str]] = {}        # principal -> permissions "action:resource_prefix"
        self._revoked: Set[str] = set()
        self._suspended: Set[str] = set()
        self._approvals: Dict[str, str] = {}         # request_id -> approver

    def _log(self, event: str, **f) -> None:
        if self._audit:
            self._audit.record(event, **f)

    # --- identity -------------------------------------------------------
    def issue_token(self, principal: str) -> str:
        return f"{principal}.{self._int.sign(principal.encode())}"

    def authenticate(self, principal: str, token) -> bool:
        try:
            if not isinstance(token, str) or "." not in token:
                return False
            who, mac = token.rsplit(".", 1)
            ok = who == principal and self._int.verify(who.encode(), mac)
        except Exception:
            ok = False
        if ok and (principal in self._revoked or principal in self._suspended):
            ok = False
        self._log("auth", principal=principal, ok=ok)
        return ok

    # --- permissions ----------------------------------------------------
    def grant(self, principal: str, action: str, resource_prefix: str) -> None:
        self._roles.setdefault(principal, set()).add(f"{action}:{resource_prefix}")
        self._log("grant", principal=principal, action=action, prefix=resource_prefix)

    def revoke(self, principal: str) -> None:
        self._revoked.add(principal); self._log("revoke", principal=principal)

    def suspend(self, principal: str) -> None:
        self._suspended.add(principal); self._log("suspend", principal=principal)

    def reinstate(self, principal: str) -> None:
        self._suspended.discard(principal); self._log("reinstate", principal=principal)

    def is_permitted(self, req: Request) -> bool:
        if req.principal in self._revoked or req.principal in self._suspended:
            return False
        for perm in self._roles.get(req.principal, ()):
            a, _, prefix = perm.partition(":")
            if a == req.action and req.resource.startswith(prefix):
                return True
        return False

    # --- approvals ------------------------------------------------------
    def approve(self, request_id: str, approver: str) -> None:
        self._approvals[request_id] = approver
        self._log("approve", request_id=request_id, approver=approver)

    def has_approval(self, req: Request) -> bool:
        approver = self._approvals.get(req.request_id)
        return bool(approver) and approver != req.principal   # no self-approval

    def decide(self, req: Request) -> Decision:
        """Policy decision: authenticated + permitted. Unknown -> BLOCK."""
        try:
            if not self.authenticate(req.principal, req.credentials):
                d = Decision.BLOCK
            elif not self.is_permitted(req):
                d = Decision.BLOCK
            else:
                d = Decision.ALLOW
        except Exception:
            d = Decision.ERROR
        self._log("policy", request_id=req.request_id, decision=d.value)
        return d
