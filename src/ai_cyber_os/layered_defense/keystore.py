"""Persistent local signing key with restrictive permissions and environment override."""
from __future__ import annotations
import os, secrets
from .crypto_integrity import EnvKeyProvider, KeyError_


class FileKeyProvider:
    def __init__(self, state_dir: str):
        self.state_dir, self.path = state_dir, os.path.join(state_dir, "key")

    def _ensure(self):
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        try: os.chmod(self.state_dir, 0o700)
        except OSError: pass
        ignore = os.path.join(self.state_dir, ".gitignore")
        if not os.path.exists(ignore):
            with open(ignore, "x", encoding="utf-8") as stream: stream.write("*\n")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return
        with os.fdopen(fd, "w", encoding="ascii") as stream: stream.write(secrets.token_hex(32))

    def get_key(self, key_id: str) -> bytes:
        if key_id != "default": raise KeyError_(f"key '{key_id}' not configured")
        self._ensure()
        try:
            with open(self.path, encoding="ascii") as stream: key = bytes.fromhex(stream.read().strip())
        except Exception as exc: raise KeyError_("key file unreadable or invalid") from exc
        if len(key) < 16: raise KeyError_("key too short (minimum 16 bytes)")
        return key


class DefaultKeyProvider:
    def __init__(self, state_dir: str):
        self._env, self._file = EnvKeyProvider(), FileKeyProvider(state_dir)

    def get_key(self, key_id: str) -> bytes:
        if os.environ.get(f"AI_CYBER_KEY_{key_id.upper()}"): return self._env.get_key(key_id)
        return self._file.get_key(key_id)
