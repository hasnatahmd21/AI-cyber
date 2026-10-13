"""Self-managed signing key with symlink/hard-link and permission checks.

Order: environment key AI_CYBER_KEY_<ID> wins; otherwise a persistent private
key in <repo>/.ai_cyber/key is created on first start. Existing unsafe key paths
or overly broad file/directory permissions fail closed.
"""
from __future__ import annotations

import os
import secrets
import stat

from .crypto_integrity import EnvKeyProvider, KeyError_


class FileKeyProvider:
    def __init__(self, state_dir: str) -> None:
        self.state_dir = os.path.abspath(state_dir)
        self.path = os.path.join(self.state_dir, "key")

    @staticmethod
    def _require_private_directory(path: str) -> None:
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise KeyError_("private state directory is unreadable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise KeyError_("private state directory must be a real directory, not a link")
        if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
            raise KeyError_("private state directory permissions must exclude group/other access")

    def _ensure(self) -> None:
        try:
            os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise KeyError_("cannot create private state directory") from exc
        self._require_private_directory(self.state_dir)

        # The directory itself is private; this file is only for keeping the state
        # directory out of version control and never contains application data.
        gi = os.path.join(self.state_dir, ".gitignore")
        if not os.path.lexists(gi):
            try:
                fd = os.open(
                    gi,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
            except FileExistsError:
                fd = None
            except OSError as exc:
                raise KeyError_("cannot safely create private state .gitignore") from exc
            if fd is not None:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write("*\n")
                    f.flush()
                    os.fsync(f.fileno())

        try:
            fd = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            return
        except OSError as exc:
            raise KeyError_("cannot safely create signing key") from exc

        try:
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(secrets.token_hex(32))
                f.flush()
                os.fsync(f.fileno())
        except Exception as exc:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            raise KeyError_("cannot persist signing key safely") from exc

    def get_key(self, key_id: str) -> bytes:
        if key_id != "default":
            raise KeyError_(f"key '{key_id}' not configured")
        self._ensure()
        fd = None
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise KeyError_("signing key path must be a regular file")
            if info.st_nlink != 1:
                raise KeyError_("hard-linked signing key is not permitted")
            if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
                raise KeyError_("signing key permissions must be owner-only")
            with os.fdopen(fd, "r", encoding="ascii") as f:
                fd = None
                raw = f.read().strip()
            k = bytes.fromhex(raw)
        except KeyError_:
            raise
        except Exception as exc:
            raise KeyError_("key file unreadable, linked, or invalid") from exc
        finally:
            if fd is not None:
                os.close(fd)
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
