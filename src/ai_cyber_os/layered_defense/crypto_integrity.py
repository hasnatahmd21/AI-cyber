"""HMAC-SHA256 integrity primitives for the layered defence package."""
from __future__ import annotations
import hashlib
import hmac
import os
from typing import Dict, Protocol
from .contracts import SecurityError


class KeyError_(SecurityError):
    pass


class KeyProvider(Protocol):
    def get_key(self, key_id: str) -> bytes: ...


class EnvKeyProvider:
    def get_key(self, key_id: str) -> bytes:
        value = os.environ.get(f"AI_CYBER_KEY_{key_id.upper()}")
        if not value:
            raise KeyError_(f"key '{key_id}' not configured")
        try:
            key = bytes.fromhex(value)
        except ValueError as exc:
            raise KeyError_("key is not valid hex") from exc
        if len(key) < 16:
            raise KeyError_("key too short (minimum 16 bytes)")
        return key


class StaticKeyProvider:
    def __init__(self, keys: Dict[str, bytes]) -> None:
        self._keys = dict(keys)

    def get_key(self, key_id: str) -> bytes:
        key = self._keys.get(key_id)
        if key is None or len(key) < 16:
            raise KeyError_(f"key '{key_id}' missing or too short")
        return key


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Integrity:
    def __init__(self, provider: KeyProvider, key_id: str = "default") -> None:
        self._provider, self._key_id = provider, key_id

    def sign(self, data: bytes) -> str:
        return hmac.new(self._provider.get_key(self._key_id), data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, mac: str) -> bool:
        try:
            return hmac.compare_digest(self.sign(data), mac)
        except Exception:
            return False


def verify_file_hash(path: str, expected_sha256: str) -> bool:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        return hmac.compare_digest(digest.hexdigest(), expected_sha256)
    except Exception:
        return False
