import unittest
from ai_cyber.contracts import Decision, Request, Sensitivity, LayerResult
from ai_cyber.layer3 import Layer3
from .helpers import trust


class T(unittest.TestCase):
    def setUp(self):
        self.t = trust(); self.tok = self.t.issue_token("alice"); self.l = Layer3(self.t)

    def crit(self, **kw):
        base = dict(request_id="c1", principal="alice", action="delete", resource="/docs/a", credentials=self.tok,
                    sensitivity=Sensitivity.CRITICAL)
        base.update(kw); return Request(**base)

    def test_non_critical_still_checks_authz(self):
        self.assertIs(self.l.evaluate(Request("r", "alice", "read", "/docs/a", None, self.tok)).decision, Decision.ALLOW)
        self.assertIs(self.l.evaluate(Request("r", "alice", "read", "/docs/a", None, "bad")).decision, Decision.BLOCK)

    def test_critical_needs_approval(self):
        self.assertIs(self.l.evaluate(self.crit()).decision, Decision.ESCALATE)

    def test_critical_with_approval_allowed(self):
        self.t.approve("c1", "carol")
        self.assertIs(self.l.evaluate(self.crit()).decision, Decision.ALLOW)

    def test_self_approval_rejected(self):
        self.t.approve("c1", "alice")
        self.assertIs(self.l.evaluate(self.crit()).decision, Decision.ESCALATE)

    def test_critical_unauthorized_blocks_even_if_approved(self):
        self.t.approve("c1", "carol")
        self.assertIs(self.l.evaluate(self.crit(credentials="bad")).decision, Decision.BLOCK)

    def test_critical_prefix(self):
        self.t.grant("alice", "read", "/keys/")
        r = Request("k1", "alice", "read", "/keys/x", None, self.tok)
        self.assertTrue(self.l.is_critical(r))
        self.assertIs(self.l.evaluate(r).decision, Decision.ESCALATE)

    def test_fail_closed_on_internal_error(self):
        class Boom:
            def decide(self, r): raise RuntimeError("x")
            def has_approval(self, r): raise RuntimeError("x")
        res = Layer3(Boom()).evaluate(self.crit())
        self.assertIs(res.decision, Decision.BLOCK); self.assertEqual(res.reason, "fail_closed")

if __name__ == "__main__":
    unittest.main()
