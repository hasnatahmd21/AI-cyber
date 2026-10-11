import json, os, shutil, tempfile, unittest

from ai_cyber import launcher
from ai_cyber.crypto_integrity import Integrity
from ai_cyber.integrity_gate import write_baseline
from tests.helpers import KEY


class TestIntegrityGate(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); d = t.name
        self.hy = os.path.join(d, "ai_cyber_os"); os.makedirs(self.hy)
        for n, c in (("a.py", "x=1\n"), ("b.py", "y=2\n")):
            with open(os.path.join(self.hy, n), "w") as f: f.write(c)
        self.clean = os.path.join(d, "clean"); shutil.copytree(self.hy, self.clean)
        self.bl = os.path.join(d, "bl", "b.json")
        write_baseline(self.hy, self.bl, Integrity(KEY))
        self.defence = os.path.join(d, "layered_defense", "ai_cyber"); os.makedirs(self.defence)
        with open(os.path.join(self.defence, "barrier.py"), "w") as f: f.write("TRUSTED = True\n")
        self.defence_clean = os.path.join(d, "defence_clean"); shutil.copytree(self.defence, self.defence_clean)
        self.def_bl = os.path.join(d, "bl", "defence_baseline.json")
        write_baseline(self.defence, self.def_bl, Integrity(KEY))
        self.calls = []

    def _run(self, argv=None, **kw):
        out = []
        rc = launcher.run(["--go"] if argv is None else argv,
                          hydra_main=lambda a: self.calls.append(a) or 0, key_provider=KEY,
                          out=out.append, hydra_dir=self.hy, baseline_path=self.bl,
                          defence_dir=self.defence, defence_baseline_path=self.def_bl, **kw)
        return rc, "\n".join(out)

    def test_clean_tree_runs(self):
        rc, out = self._run(); self.assertEqual((rc, len(self.calls)), (0, 1)); self.assertIn("integrity: OK", out)

    def test_unlisted_hydra_file_refuses_to_start(self):
        with open(os.path.join(self.hy, "unlisted.py"), "w") as f: f.write("import evil\\n")
        rc, out = self._run()
        self.assertEqual((rc, self.calls), (4, []))
        self.assertIn("HYDRA code changed", out)

    def test_symlinked_hydra_entry_refuses_cleanly(self):
        os.symlink(os.path.join(self.hy, "a.py"), os.path.join(self.hy, "alias.py"))
        rc, out = self._run()
        self.assertEqual((rc, self.calls), (4, []))
        self.assertIn("could not be safely inspected", out)

    def test_modified_hydra_file_refuses_to_start(self):
        with open(os.path.join(self.hy, "a.py"), "a") as f: f.write("evil()\n")
        rc, _ = self._run(); self.assertEqual((rc, self.calls), (4, []))

    def test_drift_with_clean_source_restores_then_requires_fresh_process(self):
        with open(os.path.join(self.hy, "a.py"), "a") as f: f.write("evil()\n")
        os.remove(os.path.join(self.hy, "b.py"))
        rc, out = self._run(clean_source=self.clean)
        self.assertEqual((rc, self.calls), (4, [])); self.assertIn("restored=2", out)
        with open(os.path.join(self.hy, "a.py")) as f: self.assertEqual(f.read(), "x=1\n")
        rc, _ = self._run()
        self.assertEqual((rc, len(self.calls)), (0, 1))

    def test_modified_defence_module_refuses_to_start(self):
        with open(os.path.join(self.defence, "barrier.py"), "a") as f: f.write("UNTRUSTED = True\n")
        rc, out = self._run()
        self.assertEqual((rc, self.calls), (4, []))
        self.assertIn("defence implementation changed", out)

    def test_defence_restore_blocks_current_process_then_restarts_clean(self):
        with open(os.path.join(self.defence, "barrier.py"), "a") as f: f.write("UNTRUSTED = True\n")
        rc, out = self._run(defence_clean_source=self.defence_clean)
        self.assertEqual((rc, self.calls), (4, []))
        self.assertIn("restart required", out)
        with open(os.path.join(self.defence, "barrier.py")) as f: self.assertEqual(f.read(), "TRUSTED = True\n")
        rc, _ = self._run()
        self.assertEqual((rc, len(self.calls)), (0, 1))

    def test_dirty_clean_source_is_refused(self):
        with open(os.path.join(self.hy, "a.py"), "a") as f: f.write("evil()\n")
        with open(os.path.join(self.clean, "a.py"), "a") as f: f.write("also evil\n")
        rc, _ = self._run(clean_source=self.clean); self.assertEqual((rc, self.calls), (4, []))

    def test_forged_baseline_is_refused(self):
        with open(self.bl) as f: doc = json.load(f)
        doc["baseline"]["a.py"] = "0" * 64
        with open(self.bl, "w") as f: json.dump(doc, f)
        rc, _ = self._run(clean_source=self.clean); self.assertEqual((rc, self.calls), (4, []))

    def test_missing_baseline_refuses(self):
        os.remove(self.bl); rc, _ = self._run(); self.assertEqual((rc, self.calls), (4, []))

    def test_barrier_and_layers_still_apply_after_integrity_ok(self):
        rc, _ = self._run([";rm " + "rf /"])
        self.assertEqual((rc, self.calls), (3, []))


if __name__ == "__main__":
    unittest.main()
