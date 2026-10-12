import os, tempfile, unittest

from ai_cyber import launcher
from ai_cyber.adapters.audit_store import load_verified_encrypted
from ai_cyber.contracts import Decision
from ai_cyber.crypto_encryption import AeadCipher
from ai_cyber.crypto_integrity import Integrity
from ai_cyber.integrity_gate import write_baseline
from ai_cyber.runtime import StartupError, build_system
from tests.helpers import KEY


class TestLauncher(unittest.TestCase):
    def _run(self, argv, hydra, **kw):
        out = []
        with tempfile.TemporaryDirectory() as root:
            target = os.path.join(root, "src", "ai_cyber_os")
            os.makedirs(target)
            with open(os.path.join(target, "runtime.py"), "w") as f:
                f.write("TRUSTED = True\\n")
            baseline = os.path.join(root, ".ai_cyber", "hydra_baseline.json")
            write_baseline(target, baseline, Integrity(KEY))
            defence = os.path.join(root, "layered_defense", "ai_cyber")
            os.makedirs(defence)
            with open(os.path.join(defence, "barrier.py"), "w") as f:
                f.write("TRUSTED = True\n")
            defence_baseline = os.path.join(root, ".ai_cyber", "defence_baseline.json")
            write_baseline(defence, defence_baseline, Integrity(KEY))
            rc = launcher.run(
                argv, hydra_main=hydra, key_provider=KEY, out=out.append,
                hydra_dir=target, baseline_path=baseline,
                defence_dir=defence, defence_baseline_path=defence_baseline, **kw
            )
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
        rc, out = self._run(["--x", "; rm " + "-rf /"], lambda a: calls.append(a) or 0)
        self.assertEqual(rc, 3); self.assertEqual(calls, [])

    def test_hydra_exit_code_is_passed_through(self):
        self.assertEqual(self._run([], lambda a: 7)[0], 7)

    def test_hydra_crash_is_reported_and_audited(self):
        def boom(a): raise RuntimeError("x")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.json.enc")
            rc, out = self._run([], boom, audit_file=p)
            self.assertEqual(rc, 1)
            events = [r["event"] for r in load_verified_encrypted(p, AeadCipher(KEY))]
            self.assertIn("hydra_crashed", events)

    def test_integrity_cannot_be_disabled_by_runtime_flag(self):
        import inspect
        self.assertNotIn("check_integrity", inspect.signature(launcher.run).parameters)

    def test_hydra_check_run_is_guarded_before_phase_execution(self):
        from types import SimpleNamespace
        from ai_cyber import __main__ as cli
        from ai_cyber import secured
        import ai_cyber.hydra as hydra_module

        events = []

        class FakeHydra:
            def verify_files(self):
                return []
            def verify_lossless(self):
                return True
            def phase_numbers(self):
                return [1]
            def run_all(self):
                events.append("hydra")
                return [SimpleNamespace(phase=1, passed=1, failed=0, ok=True, detail="")]

        original_active = secured.ACTIVE
        secured.ACTIVE = False
        self.addCleanup(setattr, secured, "ACTIVE", original_active)
        self.patch_hydra = hydra_module.Hydra
        hydra_module.Hydra = FakeHydra
        self.addCleanup(setattr, hydra_module, "Hydra", self.patch_hydra)
        self.patch_enforce = secured.enforce
        secured.enforce = lambda argv=None: events.append(("enforce", list(argv or [])))
        self.addCleanup(setattr, secured, "enforce", self.patch_enforce)

        self.assertEqual(cli.main(["hydra-check", "--run"]), 0)
        self.assertEqual(events, [("enforce", ["hydra-check", "--run"]), "hydra"])
        self.assertFalse(secured.ACTIVE)

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
