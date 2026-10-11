import unittest
from ai_cyber.contracts import Request
from ai_cyber.deception import Deception, DeceptionError
from ai_cyber.isolation import Isolation


class T(unittest.TestCase):
    def setUp(self): self.i = Isolation(); self.d = Deception(self.i); self.p = self.d.register_decoy("passwords.txt")

    def test_only_served_when_isolated(self):
        with self.assertRaises(DeceptionError): self.d.serve(Request("r", "eve", "read", self.p))
        self.i.quarantine("eve", "x")
        out = self.d.serve(Request("r", "eve", "read", self.p))
        self.assertTrue(out.startswith("DECOY:")); self.assertEqual(len(self.d.interactions), 1)

    def test_only_decoys(self):
        self.i.quarantine("eve", "x")
        with self.assertRaises(DeceptionError): self.d.serve(Request("r", "eve", "read", "/docs/real"))

    def test_decoy_content_is_synthetic(self):
        self.assertEqual(self.d._decoys[self.p], "DECOY:" + __import__("hashlib").sha256(self.p.encode()).hexdigest()[:16])

if __name__ == "__main__":
    unittest.main()
