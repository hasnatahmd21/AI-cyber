import unittest
from ai_cyber.audit_telemetry import AuditLog
from ai_cyber.contracts import Decision, Request
from .helpers import trust


class T(unittest.TestCase):
    def test_decide_matrix(self):
        t = trust(); tok = t.issue_token("alice")
        self.assertIs(t.decide(Request("r", "alice", "read", "/docs/a", None, tok)), Decision.ALLOW)
        self.assertIs(t.decide(Request("r", "alice", "read", "/other", None, tok)), Decision.BLOCK)
        self.assertIs(t.decide(Request("r", "alice", "read", "/docs/a", None, None)), Decision.BLOCK)
        self.assertIs(t.decide(Request("r", "mallory", "read", "/docs/a", None, t.issue_token("mallory"))), Decision.BLOCK)

    def test_revocation_beats_valid_token(self):
        t = trust(); tok = t.issue_token("alice"); t.revoke("alice")
        self.assertFalse(t.authenticate("alice", tok))

    def test_approval_rules(self):
        t = trust(); r = Request("r9", "alice", "delete", "/docs/a")
        self.assertFalse(t.has_approval(r)); t.approve("r9", "alice"); self.assertFalse(t.has_approval(r))
        t.approve("r9", "carol"); self.assertTrue(t.has_approval(r))

    def test_changes_are_audited_and_no_secrets_leak(self):
        t = trust(); a = t._audit
        t.suspend("alice"); t.reinstate("alice")
        ev = [r["event"] for r in a.records()]
        self.assertIn("suspend", ev); self.assertIn("reinstate", ev)
        self.assertNotIn(t.issue_token("alice").split(".")[1], str(a.records()))

    def test_malformed_token_types(self):
        t = trust()
        for bad in (None, 1, [], b"x", "no-dot"): self.assertFalse(t.authenticate("alice", bad))

if __name__ == "__main__":
    unittest.main()
