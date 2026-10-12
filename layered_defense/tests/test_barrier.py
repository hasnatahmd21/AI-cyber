import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from ai_cyber.barrier import Barrier, RateLimiter
from ai_cyber.contracts import Decision, Request
from .helpers import trust


def mk(**kw):
    t = trust()
    return Barrier(t, kw.get("limiter"), kw.get("audit")), t, t.issue_token("alice")


class ExplodingLimiter:
    def allow(self, key):
        raise RuntimeError("limiter unavailable")


class ExplodingTrust:
    def authenticate(self, principal, credentials):
        raise RuntimeError("trust unavailable")
    def is_permitted(self, req):
        return True


class ExplodingAudit:
    def record(self, event, **fields):
        raise RuntimeError("audit unavailable")


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
        for req in (
            Request("r", "alice", "format_disk", "/docs/a", None, tok),
            Request("r;x", "alice", "read", "/docs/a", None, tok),
            Request("r", "alice", "read", "/docs/../etc/passwd", None, tok),
            Request("r", "alice", "read", "/docs/a\x00", None, tok),
            Request("r", "alice", "read", "/" + "a" * 600, None, tok),
        ):
            self.assertIs(b.evaluate(req).decision, Decision.BLOCK)

    def test_encoded_path_traversal_is_blocked(self):
        b, _, tok = mk()
        paths = (
            "/docs/%2e%2e/etc/passwd", "/docs/%2E%2E/etc/passwd",
            "/docs/%2e%2e%2fetc/passwd", "/docs/%252e%252e/etc/passwd",
            "/docs/%25252e%25252e/etc/passwd", r"/docs/..\\etc\\passwd",
            "/docs/a/../../etc/passwd", "/docs/%2e%2e%5cwindows",
            "/docs/%25252e%25252e%252fetc/passwd",
        )
        for i, path in enumerate(paths):
            with self.subTest(path=path):
                result = b.evaluate(Request(f"trav{i}", "alice", "read", path, None, tok))
                self.assertIn(result.decision, (Decision.BLOCK, Decision.ERROR), path)
                self.assertEqual(result.reason, "path_traversal", path)

    def test_malformed_and_invalid_utf8_percent_encoding_blocked(self):
        b, _, tok = mk()
        for i, path in enumerate(("/docs/%", "/docs/%2", "/docs/%GG", "/docs/%2G",
                                  "/docs/%FF", "/docs/%C0%AE%C0%AE/etc/passwd",
                                  "/docs/%252", "/docs/%25GG")):
            with self.subTest(path=path):
                result = b.evaluate(Request(f"enc{i}", "alice", "read", path, None, tok))
                self.assertIs(result.decision, Decision.BLOCK)
                self.assertEqual(result.reason, "path_traversal")

    def test_safe_encoded_path_remains_allowed(self):
        b, _, tok = mk()
        result = b.evaluate(Request("safe-encoded", "alice", "read", "/docs/report%20one.txt", None, tok))
        self.assertIs(result.decision, Decision.ALLOW)

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
        self.assertEqual(d[:3], [Decision.ALLOW] * 3)
        self.assertEqual(d[3:], [Decision.BLOCK] * 2)
        now[0] = 10.0
        self.assertIs(b.evaluate(Request("rx", "alice", "read", "/docs/a", None, tok)).decision, Decision.ALLOW)

    def test_rate_limiter_concurrency_never_exceeds_capacity(self):
        capacity = 37
        limiter = RateLimiter(capacity=capacity, refill_per_sec=1.0)
        barrier = threading.Barrier(160)
        def attempt(_):
            barrier.wait(timeout=5)
            return limiter.allow("same-principal")
        with ThreadPoolExecutor(max_workers=160) as pool:
            results = list(pool.map(attempt, range(160)))
        self.assertEqual(sum(results), capacity)

    def test_rate_limiter_is_per_principal(self):
        limiter = RateLimiter(capacity=1, refill_per_sec=1.0, clock=lambda: 0.0)
        self.assertTrue(limiter.allow("alice"))
        self.assertFalse(limiter.allow("alice"))
        self.assertTrue(limiter.allow("bob"))

    def test_rate_limiter_bad_configuration_rejected(self):
        for args in ((0, 1.0), (-1, 1.0), (True, 1.0), (1, 0), (1, -1.0), (1, float("nan"))):
            with self.subTest(args=args):
                with self.assertRaises((ValueError, TypeError)):
                    RateLimiter(*args)

    def test_rate_limiter_dependency_failure_is_error(self):
        b, _, tok = mk(limiter=ExplodingLimiter())
        result = b.evaluate(Request("limfail", "alice", "read", "/docs/a", None, tok))
        self.assertIs(result.decision, Decision.ERROR)
        self.assertEqual(result.reason, "rate_limiter_error")

    def test_trust_dependency_failure_is_error(self):
        _, _, tok = mk()
        b = Barrier(ExplodingTrust(), RateLimiter())
        result = b.evaluate(Request("trustfail", "alice", "read", "/docs/a", None, tok))
        self.assertIs(result.decision, Decision.ERROR)
        self.assertEqual(result.reason, "trust_dependency_error")

    def test_audit_failure_never_allows_request(self):
        _, t, tok = mk()
        b = Barrier(t, RateLimiter(), ExplodingAudit())
        result = b.evaluate(Request("auditfail", "alice", "read", "/docs/a", None, tok))
        self.assertIs(result.decision, Decision.ERROR)
        self.assertEqual(result.reason, "audit_failure")

    def test_audit_failure_does_not_override_denial(self):
        _, t, tok = mk()
        b = Barrier(t, RateLimiter(), ExplodingAudit())
        result = b.evaluate(Request("deny-auditfail", "alice", "read", "/secret/a", None, tok))
        self.assertIs(result.decision, Decision.BLOCK)

if __name__ == "__main__":
    unittest.main()
