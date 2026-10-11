"""Honeytoken/decoy handling; touches quarantine the principal."""
from __future__ import annotations
from .contracts import AuditSink, Request
from .isolation import Isolation


class Deception:
    def __init__(self, isolation: Isolation, audit: AuditSink | None = None, decoy_prefixes=("/decoy/", "/honeytoken/")):
        self.isolation, self.audit = isolation, audit
        self.decoy_prefixes = tuple(decoy_prefixes)

    def is_decoy(self, resource: str) -> bool:
        return any(resource.startswith(p) for p in self.decoy_prefixes)

    def serve(self, request: Request) -> None:
        if self.audit: self.audit.record("decoy_access", principal=request.principal, resource=request.resource)
