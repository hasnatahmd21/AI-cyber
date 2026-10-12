from __future__ import annotations

import json
import os
import tempfile
import unittest

from ai_cyber.audit_telemetry import AuditLog
from ai_cyber.adapters.audit_store import (
    AuditTamperError,
    load_verified_encrypted,
    save_encrypted,
)
from ai_cyber.crypto_encryption import AeadCipher
from ai_cyber.crypto_integrity import StaticKeyProvider


class TestEncryptedAuditStore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "audit.json.enc")
        self.provider = StaticKeyProvider({"default": b"r" * 32})
        self.cipher = AeadCipher(self.provider)
        self.audit = AuditLog(clock=lambda: 123.0)
        self.audit.record("security_event", detail="CONFIDENTIAL_AUDIT_MARKER")
        self.audit.record("runtime_decision", decision="block", resource="/private/resource")

    def test_save_encrypts_and_round_trips_verified_chain(self):
        count = save_encrypted(self.audit, self.path, self.cipher)
        self.assertEqual(count, 2)
        with open(self.path, encoding="utf-8") as stream:
            raw = stream.read()
        self.assertNotIn("CONFIDENTIAL_AUDIT_MARKER", raw)
        self.assertNotIn("private/resource", raw)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        records = load_verified_encrypted(self.path, self.cipher, expected_len=2)
        self.assertEqual([r["event"] for r in records], ["security_event", "runtime_decision"])
        self.assertTrue(AuditLog.verify(records, expected_len=2))

    def test_ciphertext_tampering_is_rejected(self):
        save_encrypted(self.audit, self.path, self.cipher)
        with open(self.path, encoding="utf-8") as stream:
            envelope = json.load(stream)
        value = envelope["ciphertext"]
        envelope["ciphertext"] = ("A" if value[0] != "A" else "B") + value[1:]
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(envelope, f)
        with self.assertRaises(AuditTamperError):
            load_verified_encrypted(self.path, self.cipher)

    def test_wrong_key_is_rejected(self):
        save_encrypted(self.audit, self.path, self.cipher)
        wrong = AeadCipher(StaticKeyProvider({"default": b"w" * 32}))
        with self.assertRaises(AuditTamperError):
            load_verified_encrypted(self.path, wrong)

    def test_expected_length_detects_truncation(self):
        save_encrypted(self.audit, self.path, self.cipher)
        with self.assertRaises(AuditTamperError):
            load_verified_encrypted(self.path, self.cipher, expected_len=3)


if __name__ == "__main__":
    unittest.main()
