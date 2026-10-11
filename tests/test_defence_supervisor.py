from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from ai_cyber_os.layered_defense.crypto_integrity import Integrity, StaticKeyProvider
from ai_cyber_os.layered_defense.integrity_gate import write_baseline, write_file_baseline
from ai_cyber_os.layered_defense import supervisor as supervisor_module
from ai_cyber_os.layered_defense.contracts import Decision, Request
from ai_cyber_os.layered_defense.supervisor import (
    DefenceSupervisor,
    SupervisorStartupError,
    clear_defence_latch,
)


def test_supervisor_refuses_to_start_without_explicit_signed_baselines(tmp_path):
    package = tmp_path / "src" / "ai_cyber_os"
    package.mkdir(parents=True)
    (tmp_path / "IT_tech__MERGED_ALL_FIXES_APPLIED.py").write_text(
        "# test monolith placeholder\n", encoding="utf-8"
    )
    (tmp_path / ".ai_cyber").mkdir()

    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)

    with pytest.raises(SupervisorStartupError, match="baseline missing"):
        service.start()

    assert not (tmp_path / ".ai_cyber" / "hydra_baseline.json").exists()
    assert not (tmp_path / ".ai_cyber" / "it_tech_baseline.json").exists()
    assert service.snapshot()["ready"] is False


@pytest.mark.parametrize("interval", [0, -1, 60.1, True, "2"])
def test_supervisor_rejects_invalid_poll_interval(tmp_path, interval):
    with pytest.raises(ValueError):
        DefenceSupervisor(str(tmp_path), interval_s=interval)


class _FakeAudit:
    def __init__(self):
        self.entries = []
        self.health_errors = 0

    def record(self, event, **fields):
        self.entries.append({"event": event, **fields})

    def self_verify(self):
        return True


class _FakeTrust:
    def grant(self, *_args, **_kwargs):
        return None

    def issue_token(self, _principal):
        return "unit-test-token"


class _FakeNetworkGate:
    def __init__(self):
        self.ok = True
        self.reason = "IT-Tech network invariant violation"

    def health_check(self):
        return self.ok, "network healthy" if self.ok else self.reason

    def evaluate(self, _request):
        return True, "network healthy"


class _FakeAuthorityGate:
    def authorize(self, _request):
        return True, "authority allows"

    def health_check(self):
        return True, "authority state and grant healthy"


class _FakeOrchestrator:
    def __init__(self, network_gate, authority_gate):
        self.l2 = SimpleNamespace(it_tech_network=network_gate)
        self.l3 = SimpleNamespace(it_tech_gate=authority_gate)
        self.requests = []
        self.shutdown_called = False

    def handle(self, request):
        self.requests.append(request)
        return SimpleNamespace(
            decision=Decision.ALLOW,
            reason="all gates allow",
            trace=("barrier:allow", "layer1:allow", "layer2:allow", "layer3:allow"),
        )

    def shutdown(self):
        self.shutdown_called = True


class _FakeSystem:
    def __init__(self, network_gate, authority_gate):
        self.audit = _FakeAudit()
        self.trust = _FakeTrust()
        self.orchestrator = _FakeOrchestrator(network_gate, authority_gate)
        self.isolation = SimpleNamespace()
        self.deception = SimpleNamespace()

    def shutdown(self):
        self.orchestrator.shutdown()
        self.audit.record("shutdown")


def _install_fake_runtime(monkeypatch, service, system):
    monkeypatch.setattr(
        service,
        "_verify_source_assets",
        lambda: (
            True,
            "signed source baselines verified",
            {"hydra_source_integrity": True, "it_tech_source_integrity": True},
        ),
    )
    monkeypatch.setattr(supervisor_module, "build_system", lambda **_kwargs: system)
    monkeypatch.setattr(supervisor_module, "save", lambda *_args, **_kwargs: len(system.audit.entries))


def test_resident_supervisor_routes_ui_runs_through_persistent_security_pipeline(tmp_path, monkeypatch):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)

    service.start()
    try:
        allowed, reason, evidence = service.authorize_hydra("phase7", hardening=True)
        assert allowed is True, reason
        assert evidence["decision"] == "allow"
        request = system.orchestrator.requests[-1]
        assert request.source == "external"
        assert "phase=phase7" in request.payload
        assert request.resource == "hydra:run"
        assert service.snapshot()["ready"] is True
    finally:
        service.stop()

    assert system.orchestrator.shutdown_called
    assert any(entry["event"] == "supervisor_hydra_gate" for entry in system.audit.entries)


def test_resident_monitor_latches_closed_when_network_health_fails(tmp_path, monkeypatch):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)

    service.start()
    network.ok = False
    deadline = time.monotonic() + 3.0
    try:
        while time.monotonic() < deadline:
            if service.snapshot()["status"] == "blocked":
                break
            time.sleep(0.025)

        state = service.snapshot()
        assert state["status"] == "blocked"
        assert state["ready"] is False
        assert "network invariant" in state["reason"]
        allowed, reason, _evidence = service.authorize_hydra("phase1")
        assert allowed is False
        assert "not healthy" in reason
        assert any(entry["event"] == "supervisor_fail_closed" for entry in system.audit.entries)
    finally:
        service.stop()



def test_signed_incident_latch_blocks_automatic_service_restart(tmp_path, monkeypatch):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)

    service.start()
    network.ok = False
    deadline = time.monotonic() + 3.0
    try:
        while time.monotonic() < deadline:
            if service.snapshot()["status"] == "blocked":
                break
            time.sleep(0.025)
        assert service.snapshot()["status"] == "blocked"
        latch_path = tmp_path / ".ai_cyber" / "defence_latch.json"
        assert latch_path.is_file()
    finally:
        service.stop()

    restarted = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    monkeypatch.setattr(
        restarted,
        "_verify_source_assets",
        lambda: (
            True,
            "signed source baselines verified",
            {"hydra_source_integrity": True, "it_tech_source_integrity": True},
        ),
    )
    with pytest.raises(SupervisorStartupError, match="persistent defence incident latch"):
        restarted.start()
    assert restarted.snapshot()["ready"] is False


def test_clear_defence_latch_requires_clean_signed_sources_and_audits_operator_reason(tmp_path):
    import json
    from ai_cyber_os.layered_defense.audit_store import load_verified
    from ai_cyber_os.layered_defense.crypto_integrity import Integrity
    from ai_cyber_os.layered_defense.integrity_gate import write_baseline, write_file_baseline
    from ai_cyber_os.layered_defense.keystore import DefaultKeyProvider

    package = tmp_path / "src" / "ai_cyber_os"
    package.mkdir(parents=True)
    (package / "module.py").write_text("trusted_value = 1\n", encoding="utf-8")
    it_tech = tmp_path / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"
    it_tech.write_text("# signed test source\n", encoding="utf-8")
    state = tmp_path / ".ai_cyber"
    state.mkdir()
    provider = DefaultKeyProvider(str(state))
    integrity = Integrity(provider)
    hydra_baseline = state / "hydra_baseline.json"
    it_baseline = state / "it_tech_baseline.json"
    write_baseline(str(package), str(hydra_baseline), integrity)
    write_file_baseline(str(it_tech), str(it_baseline), integrity)

    document = {
        "status": "blocked",
        "detected_at": "2026-10-11T00:00:00+00:00",
        "reason": "test incident requires review",
        "checks": {"network": False},
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelope = json.dumps(
        {"document": document, "signature": integrity.sign(canonical)}
    )
    (state / "defence_latch.json").write_text(envelope, encoding="utf-8")
    # Recovery must clear both primary and fallback markers after a reviewed incident.
    (state / "defence_latch_fallback.json").write_text(envelope, encoding="utf-8")

    cleared, message = clear_defence_latch(str(tmp_path), "Reviewed incident and verified recovery")
    assert cleared is True, message
    assert not (state / "defence_latch.json").exists()
    assert not (state / "defence_latch_fallback.json").exists()

    audit_paths = list((state / "audit").glob("supervisor-latch-clear-*.jsonl"))
    assert len(audit_paths) == 1
    records = load_verified(str(audit_paths[0]), integrity=integrity)
    assert records[0]["event"] == "defence_latch_clear_requested"
    assert records[-1]["event"] == "defence_latch_cleared"
    assert records[-1]["fields"]["operator_reason"] == "Reviewed incident and verified recovery"


def test_clear_defence_latch_refuses_when_source_has_drifted(tmp_path):
    from ai_cyber_os.layered_defense.crypto_integrity import Integrity
    from ai_cyber_os.layered_defense.integrity_gate import write_baseline, write_file_baseline
    from ai_cyber_os.layered_defense.keystore import DefaultKeyProvider

    package = tmp_path / "src" / "ai_cyber_os"
    package.mkdir(parents=True)
    module = package / "module.py"
    module.write_text("trusted_value = 1\n", encoding="utf-8")
    it_tech = tmp_path / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"
    it_tech.write_text("# signed test source\n", encoding="utf-8")
    state = tmp_path / ".ai_cyber"
    state.mkdir()
    integrity = Integrity(DefaultKeyProvider(str(state)))
    write_baseline(str(package), str(state / "hydra_baseline.json"), integrity)
    write_file_baseline(str(it_tech), str(state / "it_tech_baseline.json"), integrity)
    (state / "defence_latch.json").write_text("{}", encoding="utf-8")
    module.write_text("trusted_value = 2\n", encoding="utf-8")

    cleared, message = clear_defence_latch(str(tmp_path), "Attempted reset after tamper")
    assert cleared is False
    assert "source integrity" in message
    assert (state / "defence_latch.json").exists()


def test_supervisor_rejects_symlinked_state_directory_even_without_latch(tmp_path):
    state_target = tmp_path / "state-target"
    state_target.mkdir()
    (tmp_path / ".ai_cyber").symlink_to(state_target, target_is_directory=True)

    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    reason = service._persistent_latch_reason()

    assert reason is not None
    assert "state directory is a symlink" in reason


def test_real_supervisor_stays_live_and_latches_after_it_tech_network_attack(tmp_path):
    import shutil
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    workspace = tmp_path / "AI-cyber-workspace"
    workspace.mkdir()
    shutil.copytree(
        repo / "src" / "ai_cyber_os",
        workspace / "src" / "ai_cyber_os",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    shutil.copy2(
        repo / "IT_tech__MERGED_ALL_FIXES_APPLIED.py",
        workspace / "IT_tech__MERGED_ALL_FIXES_APPLIED.py",
    )

    state_dir = workspace / ".ai_cyber"
    state_dir.mkdir()
    key_provider = StaticKeyProvider({"default": b"supervisor-e2e-key-material-32bytes"})
    integrity = Integrity(key_provider)
    write_baseline(
        str(workspace / "src" / "ai_cyber_os"),
        str(state_dir / "hydra_baseline.json"),
        integrity,
    )
    write_file_baseline(
        str(workspace / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"),
        str(state_dir / "it_tech_baseline.json"),
        integrity,
    )

    service = DefenceSupervisor(
        str(workspace),
        interval_s=0.25,
        key_provider=key_provider,
    )
    service.start()
    try:
        state = service.snapshot()
        assert state["active"] is True
        assert state["ready"] is True
        assert state["status"] == "healthy"
        assert state["checks"]["it_tech_network_engine"] is True
        assert state["checks"]["it_tech_authority_engine"] is True

        allowed, reason, evidence = service.authorize_hydra("phase1")
        assert allowed is True, reason
        assert evidence["decision"] == "allow"

        network_gate = service._system.orchestrator.l2.it_tech_network
        attack = Request(
            request_id="simulated-high-risk-network-activity",
            principal="test-attacker",
            action="read",
            resource="hydra:run",
            payload="safe-looking-payload",
            credentials="not-used-by-network-adapter",
            source="internal",
            attributes={"network_risk": 0.99},
        )
        for _ in range(5):
            allowed, reason = network_gate.evaluate(attack)
            assert allowed is False
            assert "risk threshold" in reason

        healthy, reason = network_gate.health_check()
        assert healthy is False, reason

        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            if service.snapshot()["status"] == "blocked":
                break
            time.sleep(0.025)

        blocked = service.snapshot()
        assert blocked["status"] == "blocked"
        assert blocked["ready"] is False
        assert (state_dir / "defence_latch.json").is_file()
        assert any(
            record["event"] == "supervisor_fail_closed"
            for record in service._system.audit.records()
        )
    finally:
        service.stop()

    restarted = DefenceSupervisor(
        str(workspace),
        interval_s=0.25,
        key_provider=key_provider,
    )
    with pytest.raises(SupervisorStartupError, match="persistent defence incident latch"):
        restarted.start()
    assert restarted.snapshot()["ready"] is False


def test_final_layer_quarantine_is_persistently_latched_before_ui_returns(tmp_path, monkeypatch):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)
    service.start()

    def quarantine(_request):
        return SimpleNamespace(
            decision=Decision.QUARANTINE,
            reason="decoy touched; attacker quarantined",
            trace=("barrier:allow", "layer1:allow", "layer2:block", "layer3:quarantine"),
        )

    system.orchestrator.handle = quarantine
    try:
        allowed, reason, evidence = service.authorize_hydra("phase1")
        assert allowed is False
        assert "quarantine" in reason.lower()
        assert evidence["decision"] == Decision.QUARANTINE.value
        assert service.snapshot()["status"] == "blocked"
        assert service.snapshot()["ready"] is False
        assert (tmp_path / ".ai_cyber" / "defence_latch.json").is_file()
        assert any(
            entry["event"] == "supervisor_fail_closed"
            for entry in system.audit.entries
        )
    finally:
        service.stop()

    restarted = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    monkeypatch.setattr(
        restarted,
        "_verify_source_assets",
        lambda: (
            True,
            "signed source baselines verified",
            {"hydra_source_integrity": True, "it_tech_source_integrity": True},
        ),
    )
    with pytest.raises(SupervisorStartupError, match="persistent defence incident latch"):
        restarted.start()


def test_audit_append_failure_cannot_leave_supervisor_stuck_in_blocking_state(tmp_path, monkeypatch):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)
    service.start()

    original_record = system.audit.record

    def fail_incident_append(event, **fields):
        if event == "supervisor_fail_closed":
            raise OSError("simulated audit append failure")
        return original_record(event, **fields)

    monkeypatch.setattr(system.audit, "record", fail_incident_append)
    try:
        service._latch_failure("simulated authority failure", {"authority": False})
        snapshot = service.snapshot()
        assert snapshot["status"] == "blocked"
        assert snapshot["ready"] is False
        assert "audit append failed" in snapshot["reason"]
        assert (tmp_path / ".ai_cyber" / "defence_latch.json").is_file()
    finally:
        service.stop()

def test_primary_latch_write_failure_uses_signed_fallback_and_blocks_restart(tmp_path, monkeypatch):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)
    service.start()

    def fail_primary_latch(_reason, _checks):
        raise OSError("simulated primary latch path failure")

    monkeypatch.setattr(service, "_write_persistent_latch", fail_primary_latch)
    try:
        service._latch_failure("simulated network incident", {"network": False})
        state = service.snapshot()
        fallback = tmp_path / ".ai_cyber" / "defence_latch_fallback.json"
        assert state["status"] == "blocked"
        assert state["ready"] is False
        assert fallback.is_file()
        assert "signed fallback latch persisted" in state["reason"]
    finally:
        service.stop()

    restarted = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    monkeypatch.setattr(
        restarted,
        "_verify_source_assets",
        lambda: (
            True,
            "signed source baselines verified",
            {"hydra_source_integrity": True, "it_tech_source_integrity": True},
        ),
    )
    with pytest.raises(SupervisorStartupError, match="persistent defence incident latch"):
        restarted.start()
    assert restarted.snapshot()["ready"] is False


def test_supervisor_remains_blocking_if_primary_and_fallback_latch_writes_fail(
    tmp_path, monkeypatch
):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)
    service.start()

    def fail_latch(*_args, **_kwargs):
        raise OSError("simulated persistent storage failure")

    monkeypatch.setattr(service, "_write_persistent_latch", fail_latch)
    monkeypatch.setattr(service, "_write_persistent_latch_to", fail_latch)
    try:
        service._latch_failure("simulated authority incident", {"authority": False})
        state = service.snapshot()
        assert state["status"] == "blocking"
        assert state["ready"] is False
        assert "restart persistence is unavailable" in state["reason"]
        assert not (tmp_path / ".ai_cyber" / "defence_latch.json").exists()
        assert not (tmp_path / ".ai_cyber" / "defence_latch_fallback.json").exists()
        allowed, _reason, _evidence = service.authorize_hydra("phase1")
        assert allowed is False
    finally:
        service.stop()

def test_audit_persistence_failure_latches_and_never_returns_to_healthy(
    tmp_path, monkeypatch
):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)
    service.start()

    def fail_save(*_args, **_kwargs):
        raise OSError("simulated audit disk failure")

    monkeypatch.setattr(supervisor_module, "save", fail_save)
    try:
        service._persist_audit()
        state = service.snapshot()
        assert state["status"] == "blocked"
        assert state["ready"] is False
        assert "audit persistence failed" in state["reason"]
        assert (tmp_path / ".ai_cyber" / "defence_latch.json").is_file()

        time.sleep(0.35)
        state = service.snapshot()
        assert state["status"] == "blocked"
        assert state["ready"] is False
        allowed, _reason, _evidence = service.authorize_hydra("phase1")
        assert allowed is False
    finally:
        service.stop()


def test_failed_latch_write_is_retried_and_audited_when_storage_recovers(
    tmp_path, monkeypatch
):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)
    service.start()
    # Remove polling-thread races so this test controls the transient storage fault.
    service._stop.set()
    if service._thread is not None:
        service._thread.join(timeout=1)

    original_primary = service._write_persistent_latch
    original_marker = service._write_persistent_latch_to

    def fail_write(*_args, **_kwargs):
        raise OSError("simulated temporary storage failure")

    monkeypatch.setattr(service, "_write_persistent_latch", fail_write)
    monkeypatch.setattr(service, "_write_persistent_latch_to", fail_write)
    try:
        service._latch_failure("simulated incident during storage outage", {"network": False})
        assert service.snapshot()["status"] == "blocking"
        assert service.snapshot()["ready"] is False

        monkeypatch.setattr(service, "_write_persistent_latch", original_primary)
        monkeypatch.setattr(service, "_write_persistent_latch_to", original_marker)
        service._latch_failure("simulated incident during storage outage", {"network": False})

        state = service.snapshot()
        assert state["status"] == "blocked"
        assert state["ready"] is False
        assert (tmp_path / ".ai_cyber" / "defence_latch.json").is_file()
        assert any(
            entry["event"] == "supervisor_latch_persistence_recovered"
            for entry in system.audit.entries
        )
    finally:
        service.stop()

def test_startup_pipeline_denial_is_persistently_latched(tmp_path, monkeypatch):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)

    def deny_startup(request):
        system.orchestrator.requests.append(request)
        return SimpleNamespace(
            decision=Decision.BLOCK,
            reason="simulated startup defence denial",
            trace=("barrier:block",),
        )

    monkeypatch.setattr(system.orchestrator, "handle", deny_startup)
    with pytest.raises(SupervisorStartupError, match="startup defence pipeline denied"):
        service.start()

    state = service.snapshot()
    assert state["active"] is False
    assert state["ready"] is False
    assert state["status"] == "blocked"
    assert (tmp_path / ".ai_cyber" / "defence_latch.json").is_file()

    restarted = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    monkeypatch.setattr(
        restarted,
        "_verify_source_assets",
        lambda: (
            True,
            "signed source baselines verified",
            {"hydra_source_integrity": True, "it_tech_source_integrity": True},
        ),
    )
    with pytest.raises(SupervisorStartupError, match="persistent defence incident latch"):
        restarted.start()


def test_stopped_supervisor_instance_cannot_be_reused(tmp_path, monkeypatch):
    network = _FakeNetworkGate()
    authority = _FakeAuthorityGate()
    system = _FakeSystem(network, authority)
    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    _install_fake_runtime(monkeypatch, service, system)

    service.start()
    service.stop()

    with pytest.raises(SupervisorStartupError, match="cannot be restarted"):
        service.start()

def test_supervisor_latches_when_existing_signed_audit_is_tampered(tmp_path, monkeypatch):
    from ai_cyber_os.layered_defense.audit_store import save
    from ai_cyber_os.layered_defense.audit_telemetry import AuditLog

    service = DefenceSupervisor(str(tmp_path), interval_s=0.25)
    audit = AuditLog()
    audit.record("trusted prior event", outcome="safe")
    audit_path = tmp_path / ".ai_cyber" / "audit" / "prior.jsonl"
    save(audit, str(audit_path), integrity=service.integrity)
    audit_path.write_text(
        audit_path.read_text(encoding="utf-8").replace("trusted prior event", "forged prior event"),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        service,
        "_verify_source_assets",
        lambda: (
            True,
            "signed source baselines verified",
            {"hydra_source_integrity": True, "it_tech_source_integrity": True},
        ),
    )

    with pytest.raises(SupervisorStartupError, match="persistent audit verification failed"):
        service.start()

    state = service.snapshot()
    assert state["ready"] is False
    assert state["status"] == "blocked"
    assert (tmp_path / ".ai_cyber" / "defence_latch.json").is_file()

def test_clear_latch_refuses_when_persisted_audit_history_is_tampered(tmp_path):
    from ai_cyber_os.layered_defense.audit_store import save
    from ai_cyber_os.layered_defense.audit_telemetry import AuditLog
    from ai_cyber_os.layered_defense.integrity_gate import write_baseline, write_file_baseline
    from ai_cyber_os.layered_defense.keystore import DefaultKeyProvider

    package = tmp_path / "src" / "ai_cyber_os"
    package.mkdir(parents=True)
    (package / "module.py").write_text("trusted = True\n", encoding="utf-8")
    it_tech = tmp_path / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"
    it_tech.write_text("# trusted IT-Tech source\n", encoding="utf-8")
    state = tmp_path / ".ai_cyber"
    state.mkdir()
    integrity = Integrity(DefaultKeyProvider(str(state)))
    write_baseline(str(package), str(state / "hydra_baseline.json"), integrity)
    write_file_baseline(str(it_tech), str(state / "it_tech_baseline.json"), integrity)

    document = {
        "status": "blocked",
        "detected_at": "2026-10-11T00:00:00+00:00",
        "reason": "audit tamper requires review",
        "checks": {"audit_chain": False},
    }
    canonical = __import__("json").dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    (state / "defence_latch.json").write_text(
        __import__("json").dumps(
            {"document": document, "signature": integrity.sign(canonical)}
        ),
        encoding="utf-8",
    )

    audit = AuditLog()
    audit.record("trusted prior event")
    audit_path = state / "audit" / "prior.jsonl"
    save(audit, str(audit_path), integrity=integrity)
    audit_path.write_text(
        audit_path.read_text(encoding="utf-8").replace("trusted prior event", "forged prior event"),
        encoding="utf-8",
    )

    cleared, message = clear_defence_latch(str(tmp_path), "Reviewed, but audit history is corrupt")
    assert cleared is False
    assert "persistent audit verification failed" in message
    assert (state / "defence_latch.json").is_file()

