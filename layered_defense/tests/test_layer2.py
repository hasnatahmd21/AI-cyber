import unittest
from ai_cyber.contracts import Decision, Request, LayerResult
from ai_cyber.layer2 import Layer2
from .helpers import trust

L1_ALLOW = LayerResult("layer1", Decision.ALLOW)


class T(unittest.TestCase):
    def setUp(self):
        self.t = trust(); self.tok = self.t.issue_token("alice"); self.l = Layer2(self.t)

    def req(self, payload=None, cred="ok", resource="/docs/a"):
        return Request("r", "alice", "read", resource, payload, self.tok if cred == "ok" else cred)

    def test_clean(self): self.assertIs(self.l.evaluate(self.req("hi"), (L1_ALLOW,)).decision, Decision.ALLOW)

    def test_detects_layer1_bypass(self):
        # payload that layer1 regexes miss but layer2's independent rules catch
        res = self.l.evaluate(self.req("select name from users"), (L1_ALLOW,))
        self.assertIs(res.decision, Decision.BLOCK)
        self.assertIn("layer1_bypass_suspected", [f.code for f in res.findings])

    def test_does_not_trust_barrier_or_l1_pass_on_policy(self):
        res = self.l.evaluate(self.req("hi", cred="forged"), (L1_ALLOW,))
        self.assertIs(res.decision, Decision.BLOCK)

    def test_missing_layer1_result_escalates(self):
        res = self.l.evaluate(self.req("hi"), ())
        self.assertIs(res.decision, Decision.ESCALATE)

    def test_correlation_quarantines(self):
        d = [self.l.evaluate(self.req("`id` | sh"), (L1_ALLOW,)).decision for _ in range(3)]
        self.assertIs(d[-1], Decision.QUARANTINE)

    def test_strikes_expire(self):
        now = [0.0]
        l = Layer2(self.t, window_s=10, strike_limit=3, clock=lambda: now[0])
        for _ in range(2): l.evaluate(self.req("`id` | sh"), (L1_ALLOW,))
        now[0] = 100
        self.assertIs(l.evaluate(self.req("`id` | sh"), (L1_ALLOW,)).decision, Decision.BLOCK)

if __name__ == "__main__":
    unittest.main()
