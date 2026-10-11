"""Quarantine state and explicit release policy."""
from __future__ import annotations
from typing import Dict, Optional, Set
from .contracts import AuditSink, SecurityError


class IsolationError(SecurityError): pass


class Isolation:
    def __init__(self, releasers: Optional[Set[str]] = None, audit: Optional[AuditSink] = None):
        self._q: Dict[str, str] = {}
        self._releasers = set(releasers or ())
        self._audit = audit

    def quarantine(self, subject: str, reason: str) -> None:
        self._q[subject] = reason
        if self._audit: self._audit.record("quarantine", subject=subject, reason=reason)

    def is_quarantined(self, subject: str) -> bool: return subject in self._q

    def release(self, subject: str, approver: str) -> bool:
        if subject not in self._q: return False
        if approver == subject or approver not in self._releasers:
            if self._audit: self._audit.record("release_denied", subject=subject, approver=approver)
            return False
        del self._q[subject]
        if self._audit: self._audit.record("release", subject=subject, approver=approver)
        return True

    def may_access(self, subject: str, resource: str, allowed_prefix: str = "/decoy/") -> bool:
        return subject not in self._q or resource.startswith(allowed_prefix)

    def verify_state(self) -> bool:
        return all(isinstance(k, str) and k and isinstance(v, str) for k, v in self._q.items())
