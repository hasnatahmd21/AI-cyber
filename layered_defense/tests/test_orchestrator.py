import time, unittest
from ai_cyber.contracts import Decision, Request, Sensitivity, LayerResult
from ai_cyber.orchestrator import Orchestrator
from .helpers import system


def rq(i, payload=None, tok=None, **kw):
    base = dict(request_id=f"r{i}", principal="alice", action="read", resource="/docs/a", payload=payload, credentials=tok)
    base.update(kw); return Request(**base)


class T(unittest.TestCase):
    def setUp(self): self.s = system(); self.tok = self.s.trust.issue_token("alice"); self.o = self.s.orchestrator
    def tearDown(self): self.s.shutdown()

    def test_allow_trace_order(self):
        r = self.o.handle(rq(1, "hi", self.tok))
        self.assertTrue(r.authorized)
        self.assertEqual([t.split(":")[0] for t in r.trace], ["barrier", "layer1", "layer2", "layer3"])

    def test_barrier_first_and_short_circuit(self):
        r = self.o.handle(rq(2, "hi", "forged"))
        self.assertEqual(r.trace, ("barrier:block",)); self.assertFalse(r.authorized)

    def test_invalid_input_is_error(self):
        self.assertIs(self.o.handle(None).decision, Decision.ERROR)
        self.assertIs(self.o.handle("junk").decision, Decision.ERROR)

    def test_layer1_block(self):
        self.assertIs(self.o.handle(rq(3, "x' OR 1=1", self.tok)).decision, Decision.BLOCK)

    def test_restrict_is_authorized_but_restricted(self):
        r = self.o.handle(rq(4, "ok", self.tok, action="write"))
        self.assertTrue(r.authorized)
        r = self.o.handle(rq(5, "ok", self.tok, action="delete", sensitivity=Sensitivity.NORMAL))
        self.assertIs(r.decision, Decision.ESCALATE)   # delete is critical -> needs approval

    def test_critical_with_approval(self):
        self.s.trust.approve("r6", "carol")
        r = self.o.handle(rq(6, None, self.tok, action="delete", sensitivity=Sensitivity.CRITICAL))
        self.assertTrue(r.authorized, r.trace)

    def test_exception_in_layer_never_allows(self):
        class Boom:
            name = "layer2"
            def evaluate(self, *a): raise RuntimeError("x")
        o = Orchestrator(self.o.barrier, self.o.l1, Boom(), self.o.l3, self.s.isolation, self.s.deception)
        r = o.handle(rq(7, "hi", self.tok)); self.assertIs(r.decision, Decision.ERROR); o.shutdown()

    def test_timeout_never_allows(self):
        class Slow:
            name = "layer1"
            def evaluate(self, *a): time.sleep(0.5); return LayerResult("layer1", Decision.ALLOW)
        o = Orchestrator(self.o.barrier, Slow(), self.o.l2, self.o.l3, self.s.isolation, self.s.deception, timeout_s=0.05)
        r = o.handle(rq(8, "hi", self.tok)); self.assertIs(r.decision, Decision.ERROR); self.assertIn("timeout", r.reason); o.shutdown()

    def test_wrong_result_type_is_error(self):
        class Bad:
            name = "layer1"
            def evaluate(self, *a): return "allow"
        o = Orchestrator(self.o.barrier, Bad(), self.o.l2, self.o.l3, self.s.isolation, self.s.deception)
        self.assertIs(o.handle(rq(9, "hi", self.tok)).decision, Decision.ERROR); o.shutdown()

    def test_repeat_offender_quarantined_then_decoy_only(self):
        self.s.deception.register_decoy("x")
        last = None
        for i in range(10, 14): last = self.o.handle(rq(i, "`id` | sh", self.tok))
        self.assertTrue(self.s.isolation.is_quarantined("alice"), last)
        r = self.o.handle(rq(20, "hi", self.tok))
        self.assertIs(r.decision, Decision.QUARANTINE)
        r = self.o.handle(rq(21, "hi", self.tok, resource="/decoy/x"))   # barrier requires permission
        self.assertFalse(r.authorized)

    def test_decoy_touch_quarantines(self):
        p = self.s.deception.register_decoy("creds"); self.s.trust.grant("alice", "read", "/decoy/")
        r = self.o.handle(rq(30, None, self.tok, resource=p))
        self.assertIs(r.decision, Decision.QUARANTINE); self.assertTrue(self.s.isolation.is_quarantined("alice"))
        r = self.o.handle(rq(31, None, self.tok, resource=p)); self.assertEqual(r.reason, "served_decoy")

    def test_every_decision_audited_and_chain_valid(self):
        self.o.handle(rq(40, "hi", self.tok)); self.o.handle(rq(41, "hi", "bad"))
        self.assertGreaterEqual(sum(1 for r in self.s.audit.records() if r["event"] == "decision"), 2)
        self.assertTrue(self.s.audit.self_verify())

if __name__ == "__main__":
    unittest.main()
