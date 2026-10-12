import os, stat, subprocess, tempfile, unittest

from ai_cyber import secured
from ai_cyber.keystore import DefaultKeyProvider, FileKeyProvider
from ai_cyber.crypto_integrity import KeyError_


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

    def test_symlinked_signing_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            state = os.path.join(d, ".ai_cyber")
            os.makedirs(state, mode=0o700)
            outside = os.path.join(d, "outside-key")
            with open(outside, "w", encoding="ascii") as stream:
                stream.write("ab" * 32)
            os.symlink(outside, os.path.join(state, "key"))
            with self.assertRaises(KeyError_):
                FileKeyProvider(state).get_key("default")

    def test_hardlinked_signing_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            state = os.path.join(d, ".ai_cyber")
            os.makedirs(state, mode=0o700)
            key_path = os.path.join(state, "key")
            with open(key_path, "w", encoding="ascii") as stream:
                stream.write("ab" * 32)
            os.chmod(key_path, 0o600)
            os.link(key_path, os.path.join(d, "key-alias"))
            with self.assertRaises(Exception):
                FileKeyProvider(state).get_key("default")

    def test_group_or_world_readable_signing_key_is_rejected(self):
        if os.name != "posix":
            self.skipTest("POSIX permission bits are not portable to this platform")
        with tempfile.TemporaryDirectory() as d:
            provider = FileKeyProvider(os.path.join(d, ".ai_cyber"))
            provider.get_key("default")
            os.chmod(provider.path, 0o644)
            with self.assertRaises(KeyError_):
                provider.get_key("default")

    def test_symlinked_state_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "real-state")
            os.makedirs(target, mode=0o700)
            linked = os.path.join(d, "linked-state")
            os.symlink(target, linked)
            with self.assertRaises(KeyError_):
                FileKeyProvider(linked).get_key("default")


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

    def test_restore_from_git_head_requires_fresh_process(self):
        self.go()
        self.calls.clear()
        with open(os.path.join(self.hy, "a.py"), "a") as f: f.write("evil()\n")
        self.assertEqual(self.go("--defence-restore"), 4)
        self.assertEqual(self.calls, [])
        with open(os.path.join(self.hy, "a.py")) as f: self.assertEqual(f.read(), "x=1\n")
        # The on-disk tree is now clean, so a new process invocation can execute it.
        self.assertEqual(self.go(), 0)
        self.assertEqual(len(self.calls), 1)

    def test_restore_with_missing_baseline_blocks_without_creating_one(self):
        self.assertEqual(self.go("--defence-restore"), 4)
        self.assertEqual(self.calls, [])
        self.assertFalse(os.path.exists(os.path.join(self.root, ".ai_cyber", "hydra_baseline.json")))

    def test_missing_baseline_with_prior_valid_audit_history_blocks(self):
        self.assertEqual(self.go(), 0)
        state = os.path.join(self.root, ".ai_cyber")
        os.remove(os.path.join(state, "hydra_baseline.json"))
        self.calls.clear()
        self.assertEqual(self.go(), 4)
        self.assertEqual(self.calls, [])
        self.assertFalse(os.path.exists(os.path.join(state, "hydra_baseline.json")))

    def test_missing_defence_baseline_with_prior_audit_history_blocks(self):
        self.assertEqual(self.go(), 0)
        state = os.path.join(self.root, ".ai_cyber")
        os.remove(os.path.join(state, "defence_baseline.json"))
        self.calls.clear()
        self.assertEqual(self.go(), 4)
        self.assertEqual(self.calls, [])
        self.assertFalse(os.path.exists(os.path.join(state, "defence_baseline.json")))

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
