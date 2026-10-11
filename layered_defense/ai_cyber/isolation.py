"""Quarantine state, release policy, cross-boundary access control."""
from __future__ import annotations

from typing import Dict, Optional, Set

from .contracts import AuditSink, SecurityError


class IsolationError(SecurityError):
    pass


class Isolation:
    def __init__(self, releasers: Optional[Set[str]] = None, audit: Optional[AuditSink] = None) -> None:
        self._q: Dict[str, str] = {}               # subject -> reason
        self._releasers = set(releasers or ())
        self._audit = audit

    def _log(self, event: str, **f) -> None:
        if self._audit:
            self._audit.record(event, **f)

    def quarantine(self, subject: str, reason: str) -> None:
        self._q[subject] = reason
        self._log("quarantine", subject=subject, reason=reason)

    def is_quarantined(self, subject: str) -> bool:
        return subject in self._q

    def release(self, subject: str, approver: str) -> bool:
        """Release requires an authorized releaser who is not the subject."""
        if subject not in self._q:
            return False
        if approver == subject or approver not in self._releasers:
            self._log("release_denied", subject=subject, approver=approver)
            return False
        del self._q[subject]
        self._log("release", subject=subject, approver=approver)
        return True

    def may_access(self, subject: str, resource: str, allowed_prefix: str = "/decoy/") -> bool:
        """A quarantined subject may only touch the sandbox prefix; all else is blocked."""
        if subject not in self._q:
            return True
        return resource.startswith(allowed_prefix)

    def verify_state(self) -> bool:
        return all(isinstance(k, str) and k and isinstance(v, str) for k, v in self._q.items())

    def snapshot(self) -> Dict[str, str]:
        return dict(self._q)
