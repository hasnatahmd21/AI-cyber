import unittest
from ai_cyber.barrier import Barrier, RateLimiter
from ai_cyber.contracts import Decision, Request
from .helpers import trust


def mk(**kw):
    t = trust()
    return Barrier(t, kw.get("limiter")), t, t.issue_token("alice")


class T(unittest.TestCase):
    def test_valid_allowed(self):
        b, t, tok = mk()
        self.assertIs(b.evaluate(Request("r1", "alice", "read", "/docs/a", None, tok)).decision, Decision.ALLOW)

    def test_not_a_request_is_error(self):
        b, *_ = mk()
        for bad in (None, {}, "x", 5):
            self.assertIs(b.evaluate(bad).decision, Decision.ERROR)

    def test_missing_fields_error(self):
        b, _, tok = mk()
        self.assertIs(b.evaluate(Request("", "alice", "read", "/docs/a", None, tok)).decision, Decision.ERROR)
        self.assertIs(b.evaluate(Request("r", "", "read", "/docs/a", None, tok)).decision, Decision.ERROR)

    def test_bad_action_identifier_resource(self):
        b, _, tok = mk()
        self.assertIs(b.evaluate(Request("r", "alice", "format_disk", "/docs/a", None, tok)).decision, Decision.BLOCK)
        self.assertIs(b.evaluate(Request("r;x", "alice", "read", "/docs/a", None, tok)).decision, Decision.BLOCK)
        self.assertIs(b.evaluate(Request("r", "alice", "read", "/docs/../etc/passwd", None, tok)).decision, Decision.BLOCK)
        self.assertIs(b.evaluate(Request("r", "alice", "read", "/docs/a\\x00", None, tok)).decision, Decision.BLOCK)
        self.assertIs(b.evaluate(Request("r", "alice", "read", "/" + "a" * 600, None, tok)).decision, Decision.BLOCK)

    def test_encoded_path_traversal_is_blocked(self):
        b, _, tok = mk()
        paths = (
            "/docs/%2e%2e/etc/passwd",
            "/docs/%2E%2E/etc/passwd",
            "/docs/%2e%2e%2fetc/passwd",
            "/docs/%252e%252e/etc/passwd",
            "/docs/%25252e%25252e/etc/passwd",
            r"/docs/..\\etc\\passwd",
            "/docs/a/../../etc/passwd",
        )
        for i, path in enumerate(paths):
            with self.subTest(path=path):
                result = b.evaluate(Request(f"trav{i}", "alice", "read", path, None, tok))
                self.assertIn(result.decision, (Decision.BLOCK, Decision.ERROR), path)
                self.assertEqual(result.reason, "path_traversal", path)

    def test_payload_too_large(self):
        b, _, tok = mk()
        self.assertIs(b.evaluate(Request("r", "alice", "write", "/docs/a", b"x" * 1_000_001, tok)).decision, Decision.BLOCK)

    def test_auth_bypass_attempts(self):
        b, t, tok = mk()
        for cred in (None, "", "alice", "alice.", "bob." + tok.split(".")[1], tok + "0", 123):
            self.assertIs(b.evaluate(Request("r", "alice", "read", "/docs/a", None, cred)).decision, Decision.BLOCK, cred)

    def test_token_of_other_principal_rejected(self):
        b, t, _ = mk()
        t.grant("bob", "read", "/docs/")
        self.assertIs(b.evaluate(Request("r", "alice", "read", "/docs/a", None, t.issue_token("bob"))).decision, Decision.BLOCK)

    def test_authorization(self):
        b, t, tok = mk()
        self.assertIs(b.evaluate(Request("r", "alice", "read", "/secret/a", None, tok)).decision, Decision.BLOCK)

    def test_revoked_and_suspended(self):
        b, t, tok = mk()
        t.suspend("alice")
        self.assertIs(b.evaluate(Request("r", "alice", "read", "/docs/a", None, tok)).decision, Decision.BLOCK)
        t.reinstate("alice")
        self.assertIs(b.evaluate(Request("r", "alice", "read", "/docs/a", None, tok)).decision, Decision.ALLOW)
        t.revoke("alice")
        self.assertIs(b.evaluate(Request("r", "alice", "read", "/docs/a", None, tok)).decision, Decision.BLOCK)

    def test_rate_limit(self):
        now = [0.0]
        b, t, tok = mk(limiter=RateLimiter(3, 1.0, lambda: now[0]))
        d = [b.evaluate(Request(f"r{i}", "alice", "read", "/docs/a", None, tok)).decision for i in range(5)]
        self.assertEqual(d[:3], [Decision.ALLOW] * 3); self.assertEqual(d[3:], [Decision.BLOCK] * 2)
        now[0] = 10.0
        self.assertIs(b.evaluate(Request("rx", "alice", "read", "/docs/a", None, tok)).decision, Decision.ALLOW)


if __name__ == "__main__":
    unittest.main()
