from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from ai_cyber_os.layered_defense import supervisor as supervisor_module
from ai_cyber_os.layered_defense.contracts import Decision
from ai_cyber_os.layered_defense.supervisor import DefenceSupervisor, SupervisorStartupError


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
