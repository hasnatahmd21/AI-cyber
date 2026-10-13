"""Integrity (HMAC-SHA256), authenticated tamper detection, key management interface.
Uses only the standard library. Keys are NEVER hardcoded: supplied by a KeyProvider
(env var / injected). Confidentiality (AEAD) needs a vetted library; see aead_available()."""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Dict, Optional, Protocol

from .contracts import SecurityError


class KeyError_(SecurityError):
    pass


class KeyProvider(Protocol):
    def get_key(self, key_id: str) -> bytes: ...


class EnvKeyProvider:
    """Reads hex keys from env vars AI_CYBER_KEY_<ID>."""
    def get_key(self, key_id: str) -> bytes:
        v = os.environ.get(f"AI_CYBER_KEY_{key_id.upper()}")
        if not v:
            raise KeyError_(f"key '{key_id}' not configured")
        try:
            k = bytes.fromhex(v)
        except ValueError as e:
            raise KeyError_("key is not valid hex") from e
        if len(k) < 16:
            raise KeyError_("key too short (min 16 bytes)")
        return k


class StaticKeyProvider:
    """For tests / injected keys only."""
    def __init__(self, keys: Dict[str, bytes]) -> None:
        self._keys = dict(keys)
    def get_key(self, key_id: str) -> bytes:
        if key_id not in self._keys:
            raise KeyError_(f"key '{key_id}' not configured")
        k = self._keys[key_id]
        if len(k) < 16:
            raise KeyError_("key too short (min 16 bytes)")
        return k


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Integrity:
    def __init__(self, provider: KeyProvider, key_id: str = "default") -> None:
        self._p, self._id = provider, key_id

    def sign(self, data: bytes) -> str:
        return hmac.new(self._p.get_key(self._id), data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, mac: str) -> bool:
        """Constant-time; any error (missing key, bad types) -> False (fail closed)."""
        try:
            return hmac.compare_digest(self.sign(data), mac)
        except Exception:
            return False


def verify_file_hash(path: str, expected_sha256: str) -> bool:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return hmac.compare_digest(h.hexdigest(), expected_sha256)
    except Exception:
        return False


def aead_available() -> bool:
    try:
        import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
        return True
    except Exception:
        return False
