import hashlib, json, os, tempfile, unittest

from ai_cyber.adapters.audit_store import AuditTamperError, load_verified as load_audit, save as save_audit
from ai_cyber.adapters.dataset_loader import DatasetIntegrityError, load_verified
from ai_cyber.adapters.dataset_rules import compile_rules
from ai_cyber.adapters.wiring import build_system_with_datasets
from ai_cyber.contracts import Decision, Request
from tests.helpers import KEY


def make_ds(root, rules, tamper=False):
    body = json.dumps({"rules": rules}).encode()
    with open(os.path.join(root, "rules.json"), "wb") as f:
        f.write(body + (b" " if tamper else b""))
    with open(os.path.join(root, "manifest.json"), "w") as f:
        json.dump({"files": [{"path": "rules.json", "sha256": hashlib.sha256(body).hexdigest()}]}, f)
    return root


RULE = [{"code": "kev_demo", "regex": r"evil-exploit-\d+", "severity": 8}]


class TestAdapters(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup); self.d = self.t.name

    def _sys(self, rules=RULE, **kw):
        sub = os.path.join(self.d, "ds1"); os.makedirs(sub, exist_ok=True)
        return build_system_with_datasets([make_ds(sub, rules, **kw)], key_provider=KEY)

    def _req(self, s, payload):
        s.trust.grant("alice", "read", "/docs/")
        return s.orchestrator.handle(Request("r1", "alice", "read", "/docs/a.txt", payload, s.trust.issue_token("alice")))

    def test_verified_dataset_loads(self):
        self.assertEqual(len(load_verified(make_ds(self.d, RULE)).files), 1)

    def test_tampered_file_rejected(self):
        with self.assertRaises(DatasetIntegrityError): load_verified(make_ds(self.d, RULE, tamper=True))

    def test_missing_manifest_rejected(self):
        with self.assertRaises(DatasetIntegrityError): load_verified(self.d)

    def test_path_traversal_in_manifest_rejected(self):
        make_ds(self.d, RULE)
        with open(os.path.join(self.d, "manifest.json"), "w") as f:
            json.dump({"files": [{"path": "../../etc/passwd", "sha256": "0" * 64}]}, f)
        with self.assertRaises(DatasetIntegrityError): load_verified(self.d)

    def test_bad_rules_rejected(self):
        for bad in ([{"code": "x", "regex": "(a+)+$", "severity": 5}], [{"code": "x", "regex": "[", "severity": 5}],
                    [{"code": "x", "regex": "a", "severity": 99}], [{"code": "x"}]):
            ds = load_verified(make_ds(self.d, bad))
            with self.assertRaises(DatasetIntegrityError): compile_rules(ds)

    def test_dataset_rule_blocks_through_full_pipeline(self):
        s = self._sys()
        res = self._req(s, "run evil-exploit-42 now")
        self.assertIs(res.decision, Decision.BLOCK)
        self.assertEqual(res.trace[0], "barrier:allow")          # barrier still first, not bypassed
        self.assertIs(self._req(s, "hello").decision, Decision.ALLOW)

    def test_builtin_rules_still_active(self):
        self.assertIs(self._req(self._sys(), "x' OR 1=1 --").decision, Decision.BLOCK)

    def test_unverified_dataset_refuses_startup(self):
        with self.assertRaises(DatasetIntegrityError): self._sys(tamper=True)

    def test_audit_persist_and_tamper_detection(self):
        s = self._sys(); self._req(s, "hello")
        p = os.path.join(self.d, "audit.jsonl"); n = save_audit(s.audit, p)
        self.assertEqual(len(load_audit(p, expected_len=n)), n)
        with open(p) as f: lines = f.read().splitlines()
        tampered = lines[:]; tampered[1] = tampered[1].replace('"event"', '"evenT"')
        self.assertNotEqual(tampered, lines)
        with open(p, "w") as f: f.write("\n".join(tampered) + "\n")
        with self.assertRaises(AuditTamperError): load_audit(p)
        with open(p, "w") as f: f.write("\n".join(lines[:-1]) + "\n")       # truncation
        with self.assertRaises(AuditTamperError): load_audit(p, expected_len=n)


if __name__ == "__main__":
    unittest.main()
