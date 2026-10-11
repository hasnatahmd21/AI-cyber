"""Self-managed signing key: no manual key handling.
Order: env AI_CYBER_KEY_<ID> (e.g. a Codespaces secret) wins; otherwise a key file in the project's private
state dir (.ai_cyber/key, mode 0600, created automatically on first start, never committed)."""
from __future__ import annotations

import os
import secrets

from .crypto_integrity import EnvKeyProvider, KeyError_


class FileKeyProvider:
    def __init__(self, state_dir: str) -> None:
        self.state_dir = state_dir
        self.path = os.path.join(state_dir, "key")

    def _ensure(self) -> None:
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        gi = os.path.join(self.state_dir, ".gitignore")
        if not os.path.exists(gi):
            with open(gi, "w") as f:
                f.write("*\n")                                  # state dir ignores itself: key/audit never reach git
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))

    def get_key(self, key_id: str) -> bytes:
        if key_id != "default":
            raise KeyError_(f"key '{key_id}' not configured")
        self._ensure()
        try:
            with open(self.path) as f:
                k = bytes.fromhex(f.read().strip())
        except Exception as e:
            raise KeyError_("key file unreadable/invalid") from e
        if len(k) < 16:
            raise KeyError_("key too short (min 16 bytes)")
        return k


class DefaultKeyProvider:
    def __init__(self, state_dir: str) -> None:
        self._env, self._file = EnvKeyProvider(), FileKeyProvider(state_dir)

    def get_key(self, key_id: str) -> bytes:
        if os.environ.get(f"AI_CYBER_KEY_{key_id.upper()}"):
            return self._env.get_key(key_id)
        return self._file.get_key(key_id)
