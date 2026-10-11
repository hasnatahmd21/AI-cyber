import os, subprocess, sys, unittest
import ai_cyber
from ai_cyber.contracts import Decision, Request, Sensitivity
from ai_cyber.runtime import build_system, find_entry_points, StartupError
from .helpers import system, KEY

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class T(unittest.TestCase):
    def test_startup_without_key_fails_clearly(self):
        os.environ.pop("AI_CYBER_KEY_DEFAULT", None)
        with self.assertRaises(StartupError) as c: build_system({})
        self.assertIn("AI_CYBER_KEY_DEFAULT", str(c.exception))

    def test_startup_with_short_key_fails(self):
        from ai_cyber.crypto_integrity import StaticKeyProvider
        with self.assertRaises(StartupError): build_system({}, StaticKeyProvider({"default": b"x"}))

    def test_full_scenarios(self):
        s = system(); tok = s.trust.issue_token("alice")
        def go(i, **kw):
            d = dict(request_id=f"e{i}", principal="alice", action="read", resource="/docs/a", payload="hi", credentials=tok); d.update(kw)
            return s.orchestrator.handle(Request(**d))
        self.assertTrue(go(1).authorized)
        self.assertFalse(go(2, credentials="forged").authorized)
        self.assertIs(go(3, payload="'; DROP TABLE users;--").decision, Decision.BLOCK)
        self.assertIs(go(4, resource="/docs/../etc/passwd").decision, Decision.BLOCK)
        self.assertIs(go(5, principal="bob", credentials=s.trust.issue_token("bob"), action="write").decision, Decision.BLOCK)
        self.assertIs(go(6, action="delete", sensitivity=Sensitivity.CRITICAL).decision, Decision.ESCALATE)
        s.trust.approve("e7", "carol")
        self.assertTrue(go(7, action="delete", sensitivity=Sensitivity.CRITICAL).authorized)
        self.assertTrue(s.audit.self_verify()); s.shutdown()

    def test_same_controls_regardless_of_key_source(self):
        a = system(); b = build_system({"ephemeral_key": True}); b.trust.grant("alice", "read", "/docs/")
        for s in (a, b):
            tok = s.trust.issue_token("alice")
            self.assertTrue(s.orchestrator.handle(Request("x", "alice", "read", "/docs/a", "hi", tok)).authorized)
            self.assertFalse(s.orchestrator.handle(Request("y", "alice", "read", "/docs/a", "x' OR 1=1", tok)).authorized)
            s.shutdown()

    def test_entry_points_inventory(self):
        eps = find_entry_points(os.path.dirname(ai_cyber.__file__))
        self.assertIn("__main__.py", eps)
        # runtime.py must not be a false positive (AST scan, not substring scan)
        self.assertNotIn("runtime.py", eps)
        # every non-legacy entry point is intentional
        self.assertEqual([e for e in eps if not e.startswith("legacy/")], ["__main__.py"])

    def test_cli_demo_and_hydra_check(self):
        r = subprocess.run([sys.executable, "-m", "ai_cyber", "demo"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr); self.assertIn("audit chain ok: True", r.stdout)
        r = subprocess.run([sys.executable, "-m", "ai_cyber", "hydra-check"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0); self.assertIn("lossless_vs_original: True", r.stdout)

    def test_no_import_cycles(self):
        for m in ("contracts", "audit_telemetry", "crypto_integrity", "trust_authority", "barrier", "layer1", "layer2",
                  "layer3", "isolation", "deception", "regeneration", "hydra", "orchestrator", "runtime"):
            r = subprocess.run([sys.executable, "-c", f"import ai_cyber.{m}"], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{m}: {r.stderr}")

if __name__ == "__main__":
    unittest.main()
