from __future__ import annotations

import copy

import pytest

from ai_cyber.crypto_encryption import AeadCipher, EncryptionError
from ai_cyber.crypto_integrity import StaticKeyProvider


@pytest.fixture
def cipher():
    return AeadCipher(StaticKeyProvider({"default": b"k" * 32}))


def test_round_trip_bytes_and_unicode(cipher):
    for value in (b"", b"secret payload", "sensitive ✓ π"):
        envelope = cipher.encrypt(value, associated_data="record:42")
        plaintext = cipher.decrypt(envelope, associated_data="record:42")
        expected = value.encode("utf-8") if isinstance(value, str) else value
        assert plaintext == expected
        assert "key" not in envelope
        assert set(envelope) == {"version", "algorithm", "salt", "nonce", "ciphertext"}


def test_envelopes_use_fresh_salt_and_nonce(cipher):
    first = cipher.encrypt(b"same message")
    second = cipher.encrypt(b"same message")
    assert first["salt"] != second["salt"]
    assert first["nonce"] != second["nonce"]
    assert first != second


def test_ciphertext_tampering_fails_closed(cipher):
    envelope = cipher.encrypt(b"secret")
    damaged = copy.deepcopy(envelope)
    damaged["ciphertext"] = ("A" if damaged["ciphertext"][0] != "A" else "B") + damaged["ciphertext"][1:]
    with pytest.raises(EncryptionError, match="authentication failed|invalid"):
        cipher.decrypt(damaged)


def test_wrong_associated_data_fails_closed(cipher):
    envelope = cipher.encrypt(b"secret", associated_data=b"tenant-a")
    with pytest.raises(EncryptionError, match="authentication failed"):
        cipher.decrypt(envelope, associated_data=b"tenant-b")


@pytest.mark.parametrize(
    "envelope",
    [
        None,
        {},
        {"version": 2, "algorithm": "AES-256-GCM", "salt": "AA==", "nonce": "AA==", "ciphertext": "AA=="},
        {"version": 1, "algorithm": "AES-256-GCM", "salt": "!", "nonce": "AA==", "ciphertext": "AA=="},
        {"version": 1, "algorithm": "AES-256-GCM", "salt": "AA==", "nonce": "AA==", "ciphertext": "AA==", "extra": "x"},
    ],
)
def test_malformed_envelopes_fail_closed(cipher, envelope):
    with pytest.raises(EncryptionError):
        cipher.decrypt(envelope)


def test_missing_key_fails_closed():
    cipher = AeadCipher(StaticKeyProvider({}))
    with pytest.raises(EncryptionError, match="key unavailable"):
        cipher.encrypt(b"secret")


def test_unsupported_plaintext_type_is_rejected(cipher):
    with pytest.raises(TypeError):
        cipher.encrypt({"secret": True})
