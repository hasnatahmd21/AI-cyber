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

    def test_quarantined_subject_cannot_traverse_sandbox_boundary(self):
        i = Isolation(); i.quarantine("eve", "x")
        for resource in (
            "/decoy/../docs/a.txt",
            "/decoy/../../etc/passwd",
            "/decoy/%2e%2e/docs/a.txt",
            "/decoy/%252e%252e/docs/a.txt",
            r"/decoy/..\docs\a.txt",
            "/decoy/sub/../a.txt",
            "/decoy/%2e/a.txt",
        ):
            with self.subTest(resource=resource):
                self.assertFalse(i.may_access("eve", resource), resource)

    def test_quarantined_subject_cannot_use_prefix_confusion(self):
        i = Isolation(); i.quarantine("eve", "x")
        for resource in ("/decoyevil/a.txt", "/decoy-other/a.txt", "/decoy%2f..%2fdocs/a.txt"):
            with self.subTest(resource=resource):
                self.assertFalse(i.may_access("eve", resource), resource)

    def test_quarantined_subject_can_access_normal_sandbox_paths(self):
        i = Isolation(); i.quarantine("eve", "x")
        for resource in ("/decoy/a.txt", "/decoy/nested/a.txt", "/decoy/"):
            with self.subTest(resource=resource):
                self.assertTrue(i.may_access("eve", resource), resource)

    def test_malformed_or_excessively_encoded_paths_fail_closed(self):
        i = Isolation(); i.quarantine("eve", "x")
        self.assertFalse(i.may_access("eve", ""))
        self.assertFalse(i.may_access("eve", "/decoy/%252525252525252e%252525252525252e/docs"))
        self.assertFalse(i.may_access("eve", "/decoy/\x00a.txt"))

if __name__ == "__main__":
    unittest.main()
