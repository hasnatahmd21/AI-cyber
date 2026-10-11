import unittest
from ai_cyber.isolation import Isolation


class T(unittest.TestCase):
    def test_quarantine_release_policy(self):
        i = Isolation({"admin"}); i.quarantine("eve", "x")
        self.assertTrue(i.is_quarantined("eve"))
        self.assertFalse(i.release("eve", "eve")); self.assertFalse(i.release("eve", "rando"))
        self.assertTrue(i.is_quarantined("eve"))
        self.assertTrue(i.release("eve", "admin")); self.assertFalse(i.is_quarantined("eve"))

    def test_release_unknown(self): self.assertFalse(Isolation({"a"}).release("nobody", "a"))

    def test_cross_boundary_blocked(self):
        i = Isolation(); i.quarantine("eve", "x")
        self.assertFalse(i.may_access("eve", "/docs/a")); self.assertTrue(i.may_access("eve", "/decoy/a"))
        self.assertTrue(i.may_access("alice", "/docs/a"))

    def test_verify_state(self):
        i = Isolation(); i.quarantine("eve", "x"); self.assertTrue(i.verify_state())
        i._q[""] = "bad"; self.assertFalse(i.verify_state())

if __name__ == "__main__":
    unittest.main()
