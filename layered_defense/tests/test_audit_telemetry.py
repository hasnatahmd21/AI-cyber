import unittest
from ai_cyber.audit_telemetry import AuditLog, redact


class T(unittest.TestCase):
    def mk(self):
        a = AuditLog()
        for i in range(5): a.record("e", i=i)
        return a

    def test_chain_ok(self): self.assertTrue(self.mk().self_verify())

    def test_edit_detected(self):
        r = self.mk().records(); r[2]["fields"]["i"] = 99
        self.assertFalse(AuditLog.verify(r))

    def test_deletion_and_truncation_detected(self):
        a = self.mk(); r = a.records()
        self.assertFalse(AuditLog.verify(r[:2] + r[3:])); self.assertFalse(AuditLog.verify(r[1:]))
        self.assertFalse(AuditLog.verify(r[:3], expected_len=5))

    def test_malformed_input_never_raises(self):
        for bad in (None, 5, "x", [None], [{}], [{"seq": "a"}], {"a": 1}): self.assertFalse(AuditLog.verify(bad))

    def test_secret_redaction(self):
        a = AuditLog(); a.record("login", user="u", password="hunter2", nested={"api_key": "K", "ok": 1})
        s = str(a.records()); self.assertNotIn("hunter2", s); self.assertNotIn("'K'", s); self.assertIn("[REDACTED]", s)
        self.assertEqual(redact([{"token": "t"}]), [{"token": "[REDACTED]"}])

    def test_health(self): self.assertEqual(self.mk().health()["chain_ok"], True)

if __name__ == "__main__":
    unittest.main()
