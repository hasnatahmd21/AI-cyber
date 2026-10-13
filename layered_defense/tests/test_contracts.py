import unittest
from ai_cyber.contracts import Decision, is_authorized, most_severe, Request, LayerResult, Finding


class T(unittest.TestCase):
    def test_authorized_only_allow_restrict(self):
        self.assertTrue(is_authorized(Decision.ALLOW)); self.assertTrue(is_authorized(Decision.RESTRICT))
        for d in (Decision.ESCALATE, Decision.BLOCK, Decision.QUARANTINE, Decision.ERROR):
            self.assertFalse(is_authorized(d))

    def test_most_severe(self):
        self.assertIs(most_severe(Decision.ALLOW, Decision.RESTRICT), Decision.RESTRICT)
        self.assertIs(most_severe(Decision.ALLOW, Decision.QUARANTINE, Decision.BLOCK), Decision.QUARANTINE)

    def test_empty_fails_closed(self):
        self.assertIs(most_severe(), Decision.ERROR)

    def test_request_immutable(self):
        r = Request("a", "p", "read", "/x")
        with self.assertRaises(Exception):
            r.action = "write"

    def test_layer_result_severity(self):
        self.assertEqual(LayerResult("l", Decision.ALLOW, (Finding("l", "c", 5), Finding("l", "d", 9))).max_severity, 9)

    def test_no_circular_import(self):
        import importlib, sys
        for m in [m for m in sys.modules if m.startswith("ai_cyber")]:
            del sys.modules[m]
        importlib.import_module("ai_cyber.contracts")
        self.assertNotIn("ai_cyber.barrier", sys.modules)

if __name__ == "__main__":
    unittest.main()
