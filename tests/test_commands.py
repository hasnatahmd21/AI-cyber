from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from ai_cyber_os.commands import (
    CommandGatewayError,
    CommandSpec,
    ControlledCommandGateway,
)
from ai_cyber_os.situation import SituationStore


def spec(*, args=("--version",), timeout_seconds=10, max_output_bytes=65536, cwd=None, env_allowlist=()):
    return CommandSpec(
        name="probe",
        executable=sys.executable,
        allowed_argv=(tuple(args),),
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        cwd=cwd,
        env_allowlist=tuple(env_allowlist),
    )


def test_policy_requires_absolute_executable_and_exact_argv():
    with pytest.raises(CommandGatewayError, match="absolute"):
        CommandSpec(name="probe", executable="python", allowed_argv=(("--version",),))
    gateway = ControlledCommandGateway([spec()])
    denied = gateway.execute("probe", ("--version", "--help"))
    assert denied.status == "denied"
    assert denied.returncode is None


def test_no_shell_metacharacter_can_escape_exact_allowlist(tmp_path: Path):
    gateway = ControlledCommandGateway([spec()], workspace_root=tmp_path)
    denied = gateway.execute("probe", ("--version;echo injected",))
    assert denied.status == "denied"
    assert "injected" not in denied.stdout


def test_allowed_command_runs_without_inheriting_unspecified_environment(tmp_path: Path, monkeypatch):
    script = "import os; print(os.environ.get('AI_CYBER_TEST_SECRET', 'MISSING'))"
    monkeypatch.setenv("AI_CYBER_TEST_SECRET", "SHOULD_NOT_LEAK")
    policy = CommandSpec(
        name="probe",
        executable=sys.executable,
        allowed_argv=(("-c", script),),
    )
    result = ControlledCommandGateway([policy], workspace_root=tmp_path).execute("probe", ("-c", script))
    assert result.status == "executed"
    assert result.stdout.strip() == "MISSING"


def test_explicit_environment_allowlist_is_respected(tmp_path: Path, monkeypatch):
    script = "import os; print(os.environ.get('AI_CYBER_TEST_VALUE', 'MISSING'))"
    monkeypatch.setenv("AI_CYBER_TEST_VALUE", "ALLOWED")
    policy = CommandSpec(
        name="probe",
        executable=sys.executable,
        allowed_argv=(("-c", script),),
        env_allowlist=("AI_CYBER_TEST_VALUE",),
    )
    result = ControlledCommandGateway([policy], workspace_root=tmp_path).execute("probe", ("-c", script))
    assert result.ok
    assert result.stdout.strip() == "ALLOWED"


def test_cwd_escape_is_rejected(tmp_path: Path):
    outside = tmp_path.parent
    policy = spec(cwd="../")
    gateway = ControlledCommandGateway([policy], workspace_root=tmp_path)
    with pytest.raises(CommandGatewayError, match="escapes"):
        gateway.execute("probe", ("--version",))
    assert not gateway.workspace_root.samefile(outside)


def test_timeout_is_reported_and_audited(tmp_path: Path):
    store = SituationStore(tmp_path / "situation.sqlite")
    script = "import time; time.sleep(2)"
    policy = spec(args=("-c", script), timeout_seconds=1)
    result = ControlledCommandGateway([policy], workspace_root=tmp_path, audit_store=store).execute(
        "probe", ("-c", script)
    )
    assert result.status == "timed_out"
    assert result.timed_out is True
    assert result.audit_event_ids
    events = store.query(event_types=("process",))
    assert len(events) == 1
    assert events[0]["payload"]["request_id"] == result.request_id


def test_nonzero_exit_is_failure_not_exception(tmp_path: Path):
    script = "raise SystemExit(7)"
    result = ControlledCommandGateway(
        [spec(args=("-c", script))], workspace_root=tmp_path
    ).execute("probe", ("-c", script))
    assert result.status == "failed"
    assert result.returncode == 7
    assert result.ok is False


def test_output_is_bounded_in_return_value(tmp_path: Path):
    script = "print('X' * 5000)"
    policy = spec(args=("-c", script), max_output_bytes=256)
    result = ControlledCommandGateway([policy], workspace_root=tmp_path).execute(
        "probe", ("-c", script)
    )
    assert result.status == "executed"
    assert len(result.stdout.encode()) <= 256
    assert result.stdout_truncated is True


def test_denied_request_is_audited_as_alert(tmp_path: Path):
    store = SituationStore(tmp_path / "situation.sqlite")
    gateway = ControlledCommandGateway([spec()], workspace_root=tmp_path, audit_store=store)
    result = gateway.execute("unknown", ())
    assert result.status == "denied"
    alerts = store.query(event_types=("alert",))
    assert len(alerts) == 1
    assert alerts[0]["payload"]["status"] == "denied"


def test_policy_description_has_stable_hash():
    a = spec()
    b = spec()
    assert a.policy_hash == b.policy_hash
    gateway = ControlledCommandGateway([a])
    description = gateway.describe()
    assert description[0]["policy_hash"] == a.policy_hash
    assert description[0]["allowed_argv"] == [["--version"]]


def test_gateway_rejects_bad_limits():
    with pytest.raises(CommandGatewayError):
        CommandSpec(name="probe", executable=sys.executable, allowed_argv=(("--version",),), timeout_seconds=121)
    with pytest.raises(CommandGatewayError):
        CommandSpec(name="probe", executable=sys.executable, allowed_argv=(("--version",),), max_output_bytes=255)


def test_empty_gateway_and_duplicate_specs_are_rejected():
    with pytest.raises(CommandGatewayError):
        ControlledCommandGateway([])
    a = spec()
    b = spec()
    with pytest.raises(CommandGatewayError, match="duplicate"):
        ControlledCommandGateway([a, b])
