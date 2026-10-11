import json, os, shutil, tempfile, unittest
from ai_cyber.crypto_integrity import Integrity, StaticKeyProvider
from ai_cyber.regeneration import build_baseline, sign_baseline, verify_tree, regenerate, RegenerationError


def w(path, content):
    with open(path, "w") as f:
        f.write(content)


def rd(path):
    with open(path) as f:
        return f.read()


class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.clean = os.path.join(self.d, "clean"); self.live = os.path.join(self.d, "live")
        os.makedirs(os.path.join(self.clean, "sub"))
        for p, c in (("a.py", "A"), ("sub/b.py", "B")): w(os.path.join(self.clean, p), c)
        shutil.copytree(self.clean, self.live)
        self.i = Integrity(StaticKeyProvider({"default": b"z" * 32}))
        self.base = build_baseline(self.clean); self.sig = sign_baseline(self.base, self.i)

    def tearDown(self): shutil.rmtree(self.d)

    def test_clean_state_verifies(self): self.assertEqual(verify_tree(self.live, self.base), [])

    def test_recovery_of_corrupt_and_missing(self):
        w(os.path.join(self.live, "a.py"), "EVIL"); os.remove(os.path.join(self.live, "sub/b.py"))
        self.assertEqual(len(verify_tree(self.live, self.base)), 2)
        self.assertEqual(sorted(regenerate(self.live, self.clean, self.base, self.sig, self.i)), ["a.py", "sub/b.py"])
        self.assertEqual(verify_tree(self.live, self.base), [])

    def test_unexpected_file_is_detected(self):
        w(os.path.join(self.live, "unlisted.py"), "import evil")
        self.assertEqual(verify_tree(self.live, self.base), ["unexpected:unlisted.py"])

    def test_recovery_removes_unexpected_file(self):
        extra = os.path.join(self.live, "unlisted.py")
        w(extra, "import evil")
        changed = regenerate(self.live, self.clean, self.base, self.sig, self.i)
        self.assertEqual(changed, ["removed:unlisted.py"])
        self.assertFalse(os.path.exists(extra))
        self.assertEqual(verify_tree(self.live, self.base), [])

    def test_symlinked_tree_entry_is_rejected(self):
        outside = os.path.join(self.d, "outside.py")
        w(outside, "trusted = False")
        os.symlink(outside, os.path.join(self.live, "unlisted.py"))
        with self.assertRaises(RegenerationError):
            verify_tree(self.live, self.base)

    def test_hardlinked_tree_file_is_rejected(self):
        outside = os.path.join(self.d, "outside.py")
        os.link(os.path.join(self.live, "a.py"), outside)
        with self.assertRaises(RegenerationError):
            verify_tree(self.live, self.base)

    def test_orphan_bytecode_is_detected(self):
        w(os.path.join(self.live, "injected.pyc"), "untrusted bytecode")
        self.assertEqual(verify_tree(self.live, self.base), ["unexpected:injected.pyc"])

    def test_corrupted_source_rejected(self):
        w(os.path.join(self.clean, "a.py"), "EVIL"); w(os.path.join(self.live, "a.py"), "X")
        with self.assertRaises(RegenerationError): regenerate(self.live, self.clean, self.base, self.sig, self.i)
        self.assertEqual(rd(os.path.join(self.live, "a.py")), "X")   # untouched

    def test_forged_baseline_rejected(self):
        forged = dict(self.base); forged["a.py"] = "0" * 64
        with self.assertRaises(RegenerationError): regenerate(self.live, self.clean, forged, self.sig, self.i)

    def test_path_escape_rejected(self):
        evil = {"../../x": "0" * 64}
        with self.assertRaises(RegenerationError): sign_baseline(evil, self.i)
        # Even a correctly MACed but malformed manifest must be refused at use time.
        sig = self.i.sign(json.dumps(evil, sort_keys=True).encode())
        with self.assertRaises(RegenerationError): regenerate(self.live, self.clean, evil, sig, self.i)


if __name__ == "__main__":
    unittest.main()
