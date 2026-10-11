import os, re, shutil, tempfile, unittest
from ai_cyber.hydra import Hydra, HydraError, LEGACY_DIR


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.h = Hydra()

    def test_inventory(self):
        self.assertEqual(self.h.phase_numbers(), list(range(1, 43)))
        self.assertEqual(len(self.h.manifest["segments"]), 43)          # phase 3 appeared twice in the monolith
        dup = [s for s in self.h.manifest["segments"] if s["duplicate_of_previous"]]
        self.assertEqual([d["phase"] for d in dup], [3])

    def test_files_intact(self): self.assertEqual(self.h.verify_files(), [])

    def test_lossless_vs_original_monolith(self):
        self.assertTrue(self.h.verify_lossless())
        import hashlib
        orig = open(os.path.join(LEGACY_DIR, "IT_tech__MERGED_ALL_FIXES_APPLIED.py"), "rb").read()
        self.assertEqual(hashlib.sha256(orig).hexdigest(), self.h.manifest["source_sha256"])

    def test_tamper_detected(self):
        d = tempfile.mkdtemp()
        try:
            shutil.copytree(LEGACY_DIR, os.path.join(d, "legacy"), ignore=shutil.ignore_patterns("IT_tech*", "__pycache__"))
            h = Hydra(os.path.join(d, "legacy"))
            fn = h.phase_files()[5]; p = os.path.join(h.phases_dir, fn)
            with open(p, "a") as f: f.write("\n# tampered\n")
            self.assertIn(f"modified:{fn}", h.verify_files()); self.assertFalse(h.verify_lossless())
        finally: shutil.rmtree(d)

    def test_unknown_phase(self):
        with self.assertRaises(HydraError): self.h.run_phase_subprocess(99)

    def test_phase_loads_in_process_and_has_runner(self):
        for n in (1, 13, 42):
            m = self.h.load_phase(n); self.assertTrue(callable(getattr(m, "_run_all_tests", None)), n)

    def test_all_phases_have_runner_and_future_annotations(self):
        for n, fn in self.h.phase_files().items():
            src = open(os.path.join(self.h.phases_dir, fn), encoding="utf-8").read()
            self.assertIn("from __future__ import annotations", src, fn); self.assertIn("_run_all_tests", src, fn)

    def test_regression_phase13_split_fix(self):     # phase 13 needed the future import after splitting
        r = self.h.run_phase_subprocess(13); self.assertTrue(r.ok, r.detail)

    def test_full_legacy_regression(self):
        res = self.h.run_all()
        bad = [r for r in res if not r.ok]
        self.assertEqual(bad, [], bad)
        self.assertEqual(len(res), 42); self.assertGreater(sum(r.passed for r in res), 2000)

if __name__ == "__main__":
    unittest.main()
