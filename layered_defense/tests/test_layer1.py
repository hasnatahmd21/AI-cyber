import unittest
from ai_cyber.contracts import Decision, Request
from ai_cyber.layer1 import Layer1


def r(payload=None, action="read", resource="/docs/a", source="external"):
    return Request("r", "alice", action, resource, payload, source=source)


class T(unittest.TestCase):
    def setUp(self): self.l = Layer1()

    def test_clean_allow(self): self.assertIs(self.l.evaluate(r("hello world")).decision, Decision.ALLOW)

    def test_threats_blocked(self):
        for p in ("x' OR 1=1", "1 UNION SELECT pw", "<script>alert(1)</script>", "a; rm -rf /", "../../etc/passwd", b"<script>"):
            self.assertIs(self.l.evaluate(r(p)).decision, Decision.BLOCK, p)

    def test_risky_action_restricted(self):
        self.assertIs(self.l.evaluate(r("ok", action="delete")).decision, Decision.RESTRICT)
        self.assertIs(self.l.evaluate(r("ok", action="delete", source="internal")).decision, Decision.ALLOW)

    def test_structured_findings(self):
        res = self.l.evaluate(r("x' OR 1=1"))
        self.assertTrue(res.findings and res.findings[0].layer == "layer1")

    def test_binary_payload_no_crash(self):
        self.assertIsNotNone(self.l.evaluate(r(b"\xff\xfe\x00")))

if __name__ == "__main__":
    unittest.main()
