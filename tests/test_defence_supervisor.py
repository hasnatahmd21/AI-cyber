from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from ai_cyber_os.layered_defense import supervisor as supervisor_module
from ai_cyber_os.layered_defense.contracts import Decision
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
    (state / "defence_latch.json").write_text(
        json.dumps({"document": document, "signature": integrity.sign(canonical)}),
        encoding="utf-8",
    )

    cleared, message = clear_defence_latch(str(tmp_path), "Reviewed incident and verified recovery")
    assert cleared is True, message
    assert not (state / "defence_latch.json").exists()

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
