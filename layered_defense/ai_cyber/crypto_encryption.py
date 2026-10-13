"""Versioned authenticated encryption for sensitive AI-CYBER payloads.

Integrity signatures use HMAC in crypto_integrity.py. This module provides confidentiality
and tamper detection using AES-256-GCM with a per-message salt and nonce. Callers must
supply the same associated data (AAD) when decrypting; AAD is authenticated but not hidden.
"""
from __future__ import annotations

import base64
import binascii
import os
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto_integrity import KeyProvider
from .contracts import SecurityError


class EncryptionError(SecurityError):
    """Encryption/decryption failed; plaintext is never returned on authentication failure."""


_VERSION = 1
_ALGORITHM = "AES-256-GCM"
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32
_INFO = b"ai-cyber/aead/aes-256-gcm/v1"
_FIELDS = frozenset({"version", "algorithm", "salt", "nonce", "ciphertext"})


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise EncryptionError(f"invalid encrypted envelope field: {field}")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error, ValueError) as exc:
        raise EncryptionError(f"invalid base64 in encrypted envelope field: {field}") from exc


def _aad_bytes(associated_data: bytes | str | None) -> bytes:
    if associated_data is None:
        return b""
    if isinstance(associated_data, str):
        return associated_data.encode("utf-8")
    if isinstance(associated_data, bytes):
        return associated_data
    raise TypeError("associated_data must be bytes, str, or None")


class AeadCipher:
    """AES-256-GCM using a root key from the configured key provider.

    A random salt derives a purpose-separated AES key from the root key for each envelope;
    a fresh 96-bit nonce is then generated for AES-GCM. Root keys are never included in
    envelopes. The key provider must return at least 128 bits of secret key material.
    """

    def __init__(self, provider: KeyProvider, key_id: str = "default") -> None:
        self._provider = provider
        self._key_id = key_id

    def _derive(self, salt: bytes) -> bytes:
        try:
            root_key = self._provider.get_key(self._key_id)
            if not isinstance(root_key, bytes) or len(root_key) < 16:
                raise EncryptionError("key provider returned invalid/short key material")
            return HKDF(
                algorithm=hashes.SHA256(),
                length=_KEY_BYTES,
                salt=salt,
                info=_INFO,
            ).derive(root_key)
        except EncryptionError:
            raise
        except Exception as exc:
            raise EncryptionError("encryption key unavailable") from exc

    def encrypt(self, plaintext: bytes | str, associated_data: bytes | str | None = None) -> dict[str, Any]:
        if isinstance(plaintext, str):
            raw = plaintext.encode("utf-8")
        elif isinstance(plaintext, bytes):
            raw = plaintext
        else:
            raise TypeError("plaintext must be bytes or str")

        salt = os.urandom(_SALT_BYTES)
        nonce = os.urandom(_NONCE_BYTES)
        key = self._derive(salt)
        try:
            ciphertext = AESGCM(key).encrypt(nonce, raw, _aad_bytes(associated_data))
        except Exception as exc:
            raise EncryptionError("encryption failed") from exc
        return {
            "version": _VERSION,
            "algorithm": _ALGORITHM,
            "salt": _b64encode(salt),
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        }

    def decrypt(self, envelope: Mapping[str, Any], associated_data: bytes | str | None = None) -> bytes:
        if not isinstance(envelope, Mapping) or set(envelope.keys()) != _FIELDS:
            raise EncryptionError("invalid encrypted envelope shape")
        if envelope.get("version") != _VERSION or envelope.get("algorithm") != _ALGORITHM:
            raise EncryptionError("unsupported encrypted envelope version/algorithm")

        salt = _b64decode(envelope.get("salt"), "salt")
        nonce = _b64decode(envelope.get("nonce"), "nonce")
        ciphertext = _b64decode(envelope.get("ciphertext"), "ciphertext")
        if len(salt) != _SALT_BYTES or len(nonce) != _NONCE_BYTES or len(ciphertext) < 16:
            raise EncryptionError("invalid encrypted envelope lengths")

        key = self._derive(salt)
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, _aad_bytes(associated_data))
        except InvalidTag as exc:
            raise EncryptionError("ciphertext authentication failed") from exc
        except EncryptionError:
            raise
        except Exception as exc:
            raise EncryptionError("decryption failed") from exc
