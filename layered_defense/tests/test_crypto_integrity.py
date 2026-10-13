import os, tempfile, unittest
from ai_cyber.crypto_integrity import (Integrity, StaticKeyProvider, EnvKeyProvider, KeyError_, verify_file_hash, sha256_hex)


class T(unittest.TestCase):
    def setUp(self): self.i = Integrity(StaticKeyProvider({"default": b"a" * 32}))

    def test_sign_verify(self):
        m = self.i.sign(b"data"); self.assertTrue(self.i.verify(b"data", m))

    def test_tamper_detected(self):
        m = self.i.sign(b"data")
        self.assertFalse(self.i.verify(b"data2", m)); self.assertFalse(self.i.verify(b"data", m[:-1] + ("0" if m[-1] != "0" else "1")))

    def test_bad_inputs_fail_closed(self):
        for bad in (None, 5, "", b"x"): self.assertFalse(self.i.verify(b"data", bad))

    def test_different_keys_differ(self):
        o = Integrity(StaticKeyProvider({"default": b"b" * 32}))
        self.assertFalse(o.verify(b"d", self.i.sign(b"d")))

    def test_missing_or_short_key(self):
        with self.assertRaises(KeyError_): StaticKeyProvider({}).get_key("default")
        with self.assertRaises(KeyError_): StaticKeyProvider({"default": b"short"}).get_key("default")
        self.assertFalse(Integrity(StaticKeyProvider({})).verify(b"d", "ab"))

    def test_env_provider(self):
        os.environ.pop("AI_CYBER_KEY_X", None)
        with self.assertRaises(KeyError_): EnvKeyProvider().get_key("x")
        os.environ["AI_CYBER_KEY_X"] = "zz"
        with self.assertRaises(KeyError_): EnvKeyProvider().get_key("x")
        os.environ["AI_CYBER_KEY_X"] = "11" * 16
        self.assertEqual(len(EnvKeyProvider().get_key("x")), 16); del os.environ["AI_CYBER_KEY_X"]

    def test_file_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as f: f.write(b"abc")
        self.assertTrue(verify_file_hash(f.name, sha256_hex(b"abc")))
        self.assertFalse(verify_file_hash(f.name, sha256_hex(b"abd")))
        self.assertFalse(verify_file_hash(f.name + "nope", sha256_hex(b"abc"))); os.unlink(f.name)

    def test_no_hardcoded_keys_in_source(self):
        import re, ai_cyber, pathlib
        pat = re.compile(r"(secret|api_?key|password)\s*=\s*[\"'][^\"']{6,}[\"']", re.I)
        for p in pathlib.Path(ai_cyber.__file__).parent.glob("*.py"):
            self.assertIsNone(pat.search(p.read_text()), p.name)

if __name__ == "__main__":
    unittest.main()
