"""Controlled, local-first command execution gateway.

The gateway executes only explicitly registered commands with exact argv matches.
It never invokes a shell, never accepts arbitrary command strings, and records
execution/denial telemetry through the #6 SituationStore when configured.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

from .situation import SituationStore, TelemetryEvent

SCHEMA_VERSION = "controlled_command_gateway.v1"
COMMAND_STATUSES = ("executed", "failed", "timed_out", "denied")
MAX_COMMAND_NAME = 128
MAX_ARG_COUNT = 64
MAX_ARG_LENGTH = 4096
MAX_TOTAL_ARG_BYTES = 32768
MAX_OUTPUT_BYTES = 262144
MAX_TIMEOUT_SECONDS = 120


class CommandGatewayError(ValueError):
    """Raised when a command request or gateway policy is invalid."""


@dataclass(frozen=True)
class CommandSpec:
    """One exact executable + argv policy entry.

    executable must be an absolute path. Each allowed_argv item is an exact
    argv tuple; there is intentionally no shell, wildcard, prefix, or regex
    expansion in this layer.
    """

    name: str
    executable: str
    allowed_argv: tuple[tuple[str, ...], ...]
    timeout_seconds: int = 10
    max_output_bytes: int = 65536
    cwd: str | None = None
    env_allowlist: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        name = self._text(self.name, "name", MAX_COMMAND_NAME)
        executable = self._text(self.executable, "executable", 4096)
        if not Path(executable).is_absolute():
            raise CommandGatewayError("executable must be an absolute path")
        if "\x00" in executable:
            raise CommandGatewayError("executable contains NUL byte")
        if not self.allowed_argv:
            raise CommandGatewayError("allowed_argv must contain at least one exact argv set")
        if isinstance(self.timeout_seconds, bool) or not 1 <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise CommandGatewayError(
                f"timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}"
            )
        if isinstance(self.max_output_bytes, bool) or not 256 <= self.max_output_bytes <= MAX_OUTPUT_BYTES:
            raise CommandGatewayError(
                f"max_output_bytes must be between 256 and {MAX_OUTPUT_BYTES}"
            )
        cwd = None if self.cwd is None else self._text(self.cwd, "cwd", 4096)
        if cwd is not None and Path(cwd).is_absolute():
            raise CommandGatewayError("cwd must be relative to the gateway workspace_root")
        env = self._string_tuple(self.env_allowlist, "env_allowlist", max_items=64, max_len=256)
        argv_sets = []
        for argv in self.allowed_argv:
            vals = self._string_tuple(argv, "allowed_argv", max_items=MAX_ARG_COUNT, max_len=MAX_ARG_LENGTH)
            total = sum(len(v.encode("utf-8")) for v in vals)
            if total > MAX_TOTAL_ARG_BYTES:
                raise CommandGatewayError("allowed argv exceeds total byte limit")
            argv_sets.append(vals)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "executable", executable)
        object.__setattr__(self, "allowed_argv", tuple(argv_sets))
        object.__setattr__(self, "cwd", cwd)
        object.__setattr__(self, "env_allowlist", env)

    @staticmethod
    def _text(value, field, max_len):
        if not isinstance(value, str):
            raise CommandGatewayError(f"{field} must be a string")
        value = value.strip()
        if not value:
            raise CommandGatewayError(f"{field} is required")
        if "\x00" in value:
            raise CommandGatewayError(f"{field} contains NUL byte")
        if len(value) > max_len:
            raise CommandGatewayError(f"{field} exceeds maximum length {max_len}")
        return value

    @classmethod
    def _string_tuple(cls, values, field, *, max_items, max_len):
        if not isinstance(values, (tuple, list)):
            raise CommandGatewayError(f"{field} must be a sequence")
        if len(values) > max_items:
            raise CommandGatewayError(f"{field} exceeds maximum item count {max_items}")
        return tuple(cls._text(v, field, max_len) for v in values)

    @property
    def policy_hash(self) -> str:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "name": self.name,
            "executable": self.executable,
            "allowed_argv": [list(v) for v in self.allowed_argv],
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "cwd": self.cwd,
            "env_allowlist": list(self.env_allowlist),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True)
class CommandResult:
    request_id: str
    command_name: str
    status: str
    executable: str
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    started_at: str
    finished_at: str
    duration_ms: int
    audit_event_ids: tuple[str, ...]
    policy_hash: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in COMMAND_STATUSES:
            raise CommandGatewayError(f"unsupported command status: {self.status}")

    @property
    def ok(self) -> bool:
        return self.status == "executed" and self.returncode == 0 and not self.timed_out

    def as_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "command_name": self.command_name,
            "status": self.status,
            "executable": self.executable,
            "argv": list(self.argv),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "timed_out": self.timed_out,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "audit_event_ids": list(self.audit_event_ids),
            "policy_hash": self.policy_hash,
            "schema_version": self.schema_version,
            "ok": self.ok,
        }


class ControlledCommandGateway:
    """Explicit allowlist gateway for non-shell command execution.

    Safety boundary:
    * command names must map to an exact CommandSpec;
    * the executable path must be absolute;
    * argv must exactly match one pre-registered argv tuple;
    * shell execution is always disabled;
    * cwd is pinned beneath workspace_root;
    * only explicitly allowlisted environment variables are inherited;
    * timeout and captured-output limits are bounded;
    * each request is audited as telemetry when an audit store is configured.

    This is a policy gateway, not an OS sandbox. A permitted executable can
    still have whatever privileges the hosting account gives it.
    """

    SCHEMA_VERSION = SCHEMA_VERSION

    def __init__(
        self,
        specs: Iterable[CommandSpec],
        *,
        workspace_root: str | Path | None = None,
        audit_store: SituationStore | None = None,
    ) -> None:
        items = list(specs)
        if not items:
            raise CommandGatewayError("at least one CommandSpec is required")
        by_name: dict[str, CommandSpec] = {}
        for spec in items:
            if not isinstance(spec, CommandSpec):
                raise CommandGatewayError("specs must contain CommandSpec instances")
            if spec.name in by_name:
                raise CommandGatewayError(f"duplicate command spec: {spec.name}")
            by_name[spec.name] = spec

        root = Path(workspace_root).expanduser().resolve() if workspace_root is not None else Path.cwd().resolve()
        if not root.exists() or not root.is_dir():
            raise CommandGatewayError("workspace_root must exist and be a directory")

        self.specs = dict(sorted(by_name.items()))
        self.workspace_root = root
        self.audit_store = audit_store

    def describe(self) -> list[dict]:
        """Return a safe policy description without environment values."""
        return [
            {
                "name": spec.name,
                "executable": spec.executable,
                "allowed_argv": [list(v) for v in spec.allowed_argv],
                "timeout_seconds": spec.timeout_seconds,
                "max_output_bytes": spec.max_output_bytes,
                "cwd": spec.cwd,
                "env_allowlist": list(spec.env_allowlist),
                "policy_hash": spec.policy_hash,
                "schema_version": SCHEMA_VERSION,
            }
            for spec in self.specs.values()
        ]

    def _resolve_cwd(self, spec: CommandSpec) -> Path:
        candidate = (self.workspace_root / spec.cwd).resolve() if spec.cwd else self.workspace_root
        try:
            candidate.relative_to(self.workspace_root)
        except ValueError as exc:
            raise CommandGatewayError("command cwd escapes workspace_root") from exc
        if not candidate.exists() or not candidate.is_dir():
            raise CommandGatewayError("command cwd must exist and be a directory")
        return candidate

    @staticmethod
    def _validate_request(command_name: str, argv: Iterable[str]) -> tuple[str, ...]:
        if not isinstance(command_name, str) or not command_name.strip():
            raise CommandGatewayError("command_name is required")
        raw = tuple(argv)
        if len(raw) > MAX_ARG_COUNT:
            raise CommandGatewayError(f"argv exceeds maximum item count {MAX_ARG_COUNT}")
        out = []
        total = 0
        for item in raw:
            if not isinstance(item, str):
                raise CommandGatewayError("argv entries must be strings")
            if "\x00" in item:
                raise CommandGatewayError("argv contains NUL byte")
            if len(item) > MAX_ARG_LENGTH:
                raise CommandGatewayError(f"argv entry exceeds maximum length {MAX_ARG_LENGTH}")
            total += len(item.encode("utf-8"))
            out.append(item)
        if total > MAX_TOTAL_ARG_BYTES:
            raise CommandGatewayError("argv exceeds total byte limit")
        return tuple(out)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

    @staticmethod
    def _request_id(command_name: str, argv: tuple[str, ...], policy_hash: str) -> str:
        raw = json.dumps(
            {"command_name": command_name, "argv": list(argv), "policy_hash": policy_hash, "nonce": time.time_ns()},
            sort_keys=True,
            separators=(",", ":"),
        )
        return "cmd-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _bounded_text(data: bytes | None, max_bytes: int) -> tuple[str, bool]:
        raw = data or b""
        truncated = len(raw) > max_bytes
        if truncated:
            raw = raw[:max_bytes]
        return raw.decode("utf-8", errors="replace"), truncated

    def _audit(
        self,
        *,
        request_id: str,
        command_name: str,
        event_type: str,
        status: str,
        started_at: str,
        finished_at: str,
        returncode: int | None,
        timed_out: bool,
        stdout: str,
        stderr: str,
        argv: tuple[str, ...],
        policy_hash: str,
    ) -> str | None:
        if self.audit_store is None:
            return None
        payload = {
            "request_id": request_id,
            "command_name": command_name,
            "argv": list(argv),
            "policy_hash": policy_hash,
            "status": status,
            "returncode": returncode,
            "timed_out": timed_out,
            "started_at": started_at,
            "finished_at": finished_at,
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
            "stdout_bytes": len(stdout.encode("utf-8")),
            "stderr_bytes": len(stderr.encode("utf-8")),
        }
        event = TelemetryEvent(
            event_type=event_type,
            observed_at=finished_at,
            source="controlled-command-gateway",
            severity="UNKNOWN",
            subject_type="process",
            subject_id=command_name,
            action="command_execution",
            outcome=status,
            payload=payload,
        )
        return self.audit_store.ingest(event)

    def execute(self, command_name: str, argv: Iterable[str] = ()) -> CommandResult:
        """Validate the policy and execute one exact argv request."""
        command_name = command_name.strip() if isinstance(command_name, str) else command_name
        argv_tuple = self._validate_request(command_name, argv)
        spec = self.specs.get(command_name)
        request_id = self._request_id(command_name, argv_tuple, spec.policy_hash if spec else "denied")
        started_at = self._now()

        if spec is None or argv_tuple not in spec.allowed_argv:
            finished_at = self._now()
            audit_id = self._audit(
                request_id=request_id,
                command_name=command_name,
                event_type="alert",
                status="denied",
                started_at=started_at,
                finished_at=finished_at,
                returncode=None,
                timed_out=False,
                stdout="",
                stderr="",
                argv=argv_tuple,
                policy_hash=spec.policy_hash if spec else "denied",
            )
            return CommandResult(
                request_id=request_id,
                command_name=command_name,
                status="denied",
                executable=spec.executable if spec else "",
                argv=argv_tuple,
                returncode=None,
                stdout="",
                stderr="",
                stdout_truncated=False,
                stderr_truncated=False,
                timed_out=False,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=0,
                audit_event_ids=(audit_id,) if audit_id else (),
                policy_hash=spec.policy_hash if spec else "denied",
            )

        cwd = self._resolve_cwd(spec)
        env = {key: os.environ[key] for key in spec.env_allowlist if key in os.environ}
        command = [spec.executable, *argv_tuple]
        started_clock = time.monotonic()

        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd),
                env=env,
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=spec.timeout_seconds,
                check=False,
            )
            returncode = completed.returncode
            stdout, stdout_truncated = self._bounded_text(completed.stdout, spec.max_output_bytes)
            stderr, stderr_truncated = self._bounded_text(completed.stderr, spec.max_output_bytes)
            timed_out = False
            status = "executed" if returncode == 0 else "failed"
        except subprocess.TimeoutExpired as exc:
            returncode = None
            stdout, stdout_truncated = self._bounded_text(exc.stdout, spec.max_output_bytes)
            stderr, stderr_truncated = self._bounded_text(exc.stderr, spec.max_output_bytes)
            timed_out = True
            status = "timed_out"

        finished_at = self._now()
        duration_ms = int((time.monotonic() - started_clock) * 1000)
        audit_id = self._audit(
            request_id=request_id,
            command_name=command_name,
            event_type="process" if status != "denied" else "alert",
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            returncode=returncode,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            argv=argv_tuple,
            policy_hash=spec.policy_hash,
        )
        return CommandResult(
            request_id=request_id,
            command_name=command_name,
            status=status,
            executable=spec.executable,
            argv=argv_tuple,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            timed_out=timed_out,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            audit_event_ids=(audit_id,) if audit_id else (),
            policy_hash=spec.policy_hash,
        )


__all__ = [
    "SCHEMA_VERSION",
    "COMMAND_STATUSES",
    "CommandGatewayError",
    "CommandSpec",
    "CommandResult",
    "ControlledCommandGateway",
]
