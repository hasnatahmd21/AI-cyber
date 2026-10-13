"""Quarantine state, release policy, cross-boundary access control."""
from __future__ import annotations

import posixpath
from typing import Dict, Optional, Set
from urllib.parse import unquote

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

    @staticmethod
    def _canonical_resource(resource: str) -> Optional[str]:
        """Decode and canonicalize a resource path, rejecting traversal.

        Repeated decoding handles double-encoded separators/dot segments. The
        bounded loop fails closed if input is still changing after the limit.
        Backslashes are treated as separators so Windows-style traversal cannot
        bypass the POSIX-style sandbox boundary.
        """
        if not isinstance(resource, str) or not resource or "\x00" in resource:
            return None

        decoded = resource
        for _ in range(8):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        else:
            # More decoding remains possible: do not guess how a downstream
            # component might interpret this path.
            return None

        decoded = decoded.replace("\\", "/")
        parts = decoded.split("/")
        if any(part in (".", "..") for part in parts):
            return None

        # Keep path semantics explicit and collapse duplicate separators.
        return posixpath.normpath(decoded)

    def may_access(self, subject: str, resource: str, allowed_prefix: str = "/decoy/") -> bool:
        """Quarantined subjects may access only canonical paths inside the sandbox."""
        if subject not in self._q:
            return True

        canonical = self._canonical_resource(resource)
        prefix = self._canonical_resource(allowed_prefix)
        if canonical is None or prefix is None:
            return False

        # Treat the configured prefix as a directory boundary, not a raw string
        # prefix (e.g. /decoyevil must not match /decoy).
        prefix_root = prefix.rstrip("/")
        return canonical == prefix_root or canonical.startswith(prefix_root + "/")

    def verify_state(self) -> bool:
        return all(isinstance(k, str) and k and isinstance(v, str) for k, v in self._q.items())

    def snapshot(self) -> Dict[str, str]:
        return dict(self._q)
