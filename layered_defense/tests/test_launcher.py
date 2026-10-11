import os, tempfile, unittest

from ai_cyber import launcher
from ai_cyber.adapters.audit_store import load_verified
from ai_cyber.contracts import Decision
from ai_cyber.runtime import StartupError, build_system
from tests.helpers import KEY


class TestLauncher(unittest.TestCase):
    def _run(self, argv, hydra, **kw):
        out = []
        rc = launcher.run(argv, hydra_main=hydra, key_provider=KEY, out=out.append, check_integrity=False, **kw)
        return rc, out

    def test_clean_run_goes_through_every_layer_then_hydra(self):
        calls = []
        s = build_system({}, key_provider=KEY)
        res = launcher.guard(s, ["--verify"])
        self.assertIs(res.decision, Decision.ALLOW)
        self.assertEqual(res.trace, ("barrier:allow", "layer1:allow", "layer2:allow", "layer3:allow"))
        rc, out = self._run(["--verify"], lambda a: (calls.append(a), 0)[1])
        self.assertEqual((rc, calls), (0, [["--verify"]]))

    def test_malicious_args_block_and_hydra_never_starts(self):
        calls = []
        rc, out = self._run(["--x", "; rm " + "rf /"], lambda a: calls.append(a) or 0)
        self.assertEqual(rc, 3); self.assertEqual(calls, [])

    def test_hydra_exit_code_is_passed_through(self):
        self.assertEqual(self._run([], lambda a: 7)[0], 7)

    def test_hydra_crash_is_reported_and_audited(self):
        def boom(a): raise RuntimeError("x")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            rc, out = self._run([], boom, audit_file=p)
            self.assertEqual(rc, 1)
            events = [r["event"] for r in load_verified(p)]
            self.assertIn("hydra_crashed", events)

    def test_no_key_refuses_to_start(self):
        old = os.environ.pop("AI_CYBER_KEY_DEFAULT", None)
        try:
            with self.assertRaises(StartupError):
                launcher.run([], hydra_main=lambda a: 0, out=lambda *_: None)
        finally:
            if old is not None: os.environ["AI_CYBER_KEY_DEFAULT"] = old

    def test_default_loader_finds_hydra_main(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = os.path.join(d, "layered_defense", "ai_cyber"); os.makedirs(pkg)
            src = os.path.join(d, "src", "ai_cyber_os"); os.makedirs(src)
            open(os.path.join(src, "__init__.py"), "w").close()
            with open(os.path.join(src, "__main__.py"), "w") as f:
                f.write("def main(argv=None):\n    return 5\n")
            real = launcher._repo_src
            launcher._repo_src = lambda: os.path.join(d, "src")
            try:
                self.assertEqual(launcher.default_hydra_main()(["a"]), 5)
            finally:
                launcher._repo_src = real


if __name__ == "__main__":
    unittest.main()
