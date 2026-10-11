import os, stat, subprocess, tempfile, unittest

from ai_cyber import secured
from ai_cyber.keystore import DefaultKeyProvider, FileKeyProvider


def git(root, *a):
    subprocess.run(["git", "-C", root, "-c", "user.email=t@t", "-c", "user.name=t", *a], check=True, capture_output=True)


class TestKeystore(unittest.TestCase):
    def test_key_auto_created_persistent_private(self):
        with tempfile.TemporaryDirectory() as d:
            st = os.path.join(d, ".ai_cyber"); p = FileKeyProvider(st)
            k1 = p.get_key("default"); k2 = FileKeyProvider(st).get_key("default")
            self.assertEqual((k1, len(k1)), (k2, 32))
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(st, "key")).st_mode), 0o600)
            with open(os.path.join(st, ".gitignore")) as f: self.assertEqual(f.read(), "*\n")

    def test_env_key_overrides_file(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["AI_CYBER_KEY_DEFAULT"] = "ab" * 32
            try: self.assertEqual(DefaultKeyProvider(d).get_key("default"), bytes.fromhex("ab" * 32))
            finally: del os.environ["AI_CYBER_KEY_DEFAULT"]
            self.assertFalse(os.path.exists(os.path.join(d, "key")))


class TestSecured(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); self.root = t.name
        self.hy = os.path.join(self.root, "src", "ai_cyber_os"); os.makedirs(self.hy)
        with open(os.path.join(self.hy, "a.py"), "w") as f: f.write("x=1\n")
        git(self.root, "init", "-q"); git(self.root, "add", "-A"); git(self.root, "commit", "-qm", "c")
        self.calls, self.out = [], []

    def go(self, *argv):
        return secured.main(list(argv), root=self.root, hydra_main=lambda a: self.calls.append(a) or 0, out=self.out.append)

    def test_first_start_initialises_then_runs_everything(self):
        self.assertEqual(self.go("--phase", "1"), 0)
        self.assertEqual(self.calls, [["--phase", "1"]])
        txt = "\n".join(self.out)
        self.assertIn("initialised", txt); self.assertIn("integrity: OK", txt)
        self.assertIn("layer3:allow", txt); self.assertIn("audit chain ok: True", txt)
        self.assertTrue(os.listdir(os.path.join(self.root, ".ai_cyber", "audit")))

    def test_changed_hydra_code_refuses_then_rebaseline_accepts(self):
        self.go()
        with open(os.path.join(self.hy, "a.py"), "a") as f: f.write("evil()\n")
        self.calls.clear(); self.assertEqual(self.go(), 4); self.assertEqual(self.calls, [])
        with open(os.path.join(self.hy, "a.py")) as f: self.assertEqual(f.read(), "x=1\nevil()\n")
        self.assertEqual(self.go("--defence-rebaseline"), 0); self.assertEqual(len(self.calls), 1)

    def test_restore_from_git_head(self):
        self.go()
        with open(os.path.join(self.hy, "a.py"), "a") as f: f.write("evil()\n")
        self.assertEqual(self.go("--defence-restore"), 0)
        with open(os.path.join(self.hy, "a.py")) as f: self.assertEqual(f.read(), "x=1\n")

    def test_missing_baseline_with_prior_valid_audit_history_blocks(self):
        self.assertEqual(self.go(), 0)
        state = os.path.join(self.root, ".ai_cyber")
        os.remove(os.path.join(state, "hydra_baseline.json"))
        self.calls.clear()
        self.assertEqual(self.go(), 4)
        self.assertEqual(self.calls, [])
        self.assertFalse(os.path.exists(os.path.join(state, "hydra_baseline.json")))

    def test_missing_baseline_with_damaged_audit_history_blocks(self):
        state = os.path.join(self.root, ".ai_cyber")
        audit = os.path.join(state, "audit")
        os.makedirs(audit, exist_ok=True)
        with open(os.path.join(audit, "damaged.jsonl"), "w") as f:
            f.write("{not valid audit history\\n")
        self.calls.clear()
        self.assertEqual(self.go(), 4)
        self.assertEqual(self.calls, [])
        self.assertFalse(os.path.exists(os.path.join(state, "hydra_baseline.json")))

    def test_malicious_args_blocked_before_hydra(self):
        self.assertEqual(self.go(";rm " + "-rf /"), 3); self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()


class TestEnforceHook(TestSecured):
    def setUp(self):
        super().setUp(); secured.ACTIVE = False; self.addCleanup(setattr, secured, "ACTIVE", False)

    def test_hook_lets_clean_start_through_and_marks_vetted(self):
        secured.enforce(["--phase", "1"], root=self.root, out=self.out.append)
        self.assertTrue(secured.ACTIVE)

    def test_hook_stops_malicious_args_with_systemexit(self):
        with self.assertRaises(SystemExit) as c: secured.enforce([";rm " + "-rf /"], root=self.root, out=self.out.append)
        self.assertEqual(c.exception.code, 3); self.assertFalse(secured.ACTIVE)

    def test_hook_stops_tampered_hydra_code(self):
        secured.enforce([], root=self.root, out=self.out.append); secured.ACTIVE = False
        with open(os.path.join(self.hy, "a.py"), "a") as f: f.write("evil()\n")
        with self.assertRaises(SystemExit) as c: secured.enforce([], root=self.root, out=self.out.append)
        self.assertEqual(c.exception.code, 4)

    def test_no_double_run_when_hydra_main_calls_the_hook(self):
        def hydra(a):
            secured.enforce(a, root=self.root, out=self.out.append)     # what __main__.main() will do
            self.calls.append(a); return 0
        self.assertEqual(secured.main(["x"], root=self.root, hydra_main=hydra, out=self.out.append), 0)
        self.assertEqual(sum(1 for l in self.out if l.startswith("defence: allow")), 1)
        self.assertEqual(len(self.calls), 1)
