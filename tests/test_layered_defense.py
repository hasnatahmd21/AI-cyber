from __future__ import annotations

import json
import pytest
from dataclasses import replace

from ai_cyber_os.layered_defense.audit_telemetry import AuditLog
from ai_cyber_os.layered_defense.audit_store import load_verified, save, AuditTamperError
from ai_cyber_os.layered_defense.contracts import Decision, Request
from ai_cyber_os.layered_defense.crypto_integrity import Integrity, StaticKeyProvider
from ai_cyber_os.layered_defense.integrity_gate import build_baseline, check, check_file, write_baseline, write_file_baseline
from ai_cyber_os.layered_defense.runtime import StartupError, build_system


KEY = StaticKeyProvider({"default": b"unit-test-key-material-32-bytes!!"})


def _test_signed_it_tech_source(tmp_path):
    from pathlib import Path
    import shutil

    root = Path(__file__).resolve().parents[1]
    source = tmp_path / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"
    shutil.copy2(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py", source)
    state = tmp_path / ".ai_cyber"
    state.mkdir(exist_ok=True)
    baseline = state / "it_tech_baseline.json"
    write_file_baseline(str(source), str(baseline), Integrity(KEY))
    return source, baseline


def _build_verified_system(tmp_path):
    # Sign the exact source fixture with the test key, then exercise the same
    # cryptographic check performed by the production runtime builder.
    source, baseline = _test_signed_it_tech_source(tmp_path)
    return build_system(
        config={
            "it_tech_source": str(source),
            "it_tech_baseline_path": str(baseline),
            "it_tech_integrity_verified": True,
        },
        key_provider=KEY,
    )


def _allowed_request(system, payload="safe"):
    system.trust.grant("hydra-runtime", "read", "hydra:")
    token = system.trust.issue_token("hydra-runtime")
    return Request("req-1", "hydra-runtime", "read", "hydra:run", payload=payload,
                   credentials=token, source="internal")


def test_pipeline_allows_clean_internal_hydra_request(tmp_path):
    system = _build_verified_system(tmp_path)
    try:
        result = system.orchestrator.handle(_allowed_request(system))
        assert result.decision is Decision.ALLOW
        assert result.trace == ("barrier:allow", "layer1:allow", "layer2:allow", "layer3:allow")
    finally:
        system.shutdown()


def test_pipeline_blocks_shell_injection_before_hydra(tmp_path):
    system = _build_verified_system(tmp_path)
    try:
        result = system.orchestrator.handle(_allowed_request(system, "; rm -rf /"))
        assert result.decision is Decision.BLOCK
        assert result.trace[-1] == "layer1:block"
    finally:
        system.shutdown()


def test_startup_fails_closed_without_key_provider(monkeypatch):
    monkeypatch.delenv("AI_CYBER_KEY_DEFAULT", raising=False)
    try:
        build_system()
    except StartupError:
        pass
    else:
        raise AssertionError("startup should reject absent key provider")


def test_audit_jsonl_persistence_and_tamper_detection(tmp_path):
    audit = AuditLog()
    audit.record("started", principal="safe", token="do-not-persist")
    path = tmp_path / "audit.jsonl"
    assert save(audit, str(path), integrity=Integrity(KEY)) == 1
    records = load_verified(str(path), integrity=Integrity(KEY))
    assert AuditLog.verify(records)
    assert "[REDACTED]" in path.read_text()
    path.write_text(path.read_text().replace('"started"', '"forged"'))
    try:
        load_verified(str(path), integrity=Integrity(KEY))
    except AuditTamperError:
        pass
    else:
        raise AssertionError("tampered audit must be rejected")


def test_integrity_gate_detects_added_files_and_refuses_without_clean_source(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("value = 1\n")
    baseline_path = tmp_path / ".ai_cyber" / "baseline.json"
    integrity = Integrity(KEY)
    write_baseline(str(target), str(baseline_path), integrity)
    (target / "injected.py").write_text("payload = True\n")
    result = check(str(target), str(baseline_path), integrity)
    assert result.ok is False
    assert "added file" not in result.reason
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "main.py").write_text("value = 1\n")
    result = check(str(target), str(baseline_path), integrity, str(clean))
    assert result.ok is True
    assert not (target / "injected.py").exists()



def test_existing_it_tech_authority_engine_is_wired_as_layer3_gate():
    from pathlib import Path
    from ai_cyber_os.layered_defense.it_tech_adapter import ITTechAuthorityGate

    root = Path(__file__).resolve().parents[1]
    gate = ITTechAuthorityGate(
        str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"),
        baseline_verified=True,
    )
    request = Request(
        request_id="req-it-tech",
        principal="hydra-runtime",
        action="read",
        resource="hydra:run",
        payload="safe",
        credentials="not-used-by-the-independent-authority",
        source="internal",
    )
    allowed, reason = gate.authorize(request)
    assert allowed is True, reason

    suspicious = Request(
        request_id="req-suspicious",
        principal="hydra-runtime",
        action="read",
        resource="hydra:run",
        payload="safe",
        credentials=request.credentials,
        source="internal",
        attributes={"it_tech_posture": "suspicious", "it_tech_risk": 0.8, "it_tech_confidence": 0.9},
    )
    allowed, reason = gate.authorize(suspicious)
    assert allowed is False
    assert reason



def test_existing_it_tech_network_engine_enforces_trust_and_isolation_invariants():
    from pathlib import Path
    from ai_cyber_os.layered_defense.it_tech_adapter import ITTechNetworkGate

    root = Path(__file__).resolve().parents[1]
    gate = ITTechNetworkGate(
        str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"),
        baseline_verified=True,
    )
    clean = Request(
        request_id="req-network-clean",
        principal="hydra-runtime",
        action="read",
        resource="hydra:run",
        payload="safe",
        credentials="not-used-by-network-gate",
        source="internal",
    )
    allowed, reason = gate.evaluate(clean)
    assert allowed is True, reason

    risky = Request(
        request_id="req-network-risky",
        principal="hydra-runtime",
        action="read",
        resource="hydra:run",
        payload="safe",
        credentials="not-used-by-network-gate",
        source="internal",
        attributes={"network_risk": 0.9},
    )
    allowed, reason = gate.evaluate(risky)
    assert allowed is False
    assert reason



def test_audit_manifest_detects_truncation_and_requires_valid_signature(tmp_path):
    audit = AuditLog()
    audit.record("started")
    audit.record("phase_completed", status="PASS")
    path = tmp_path / "audit.jsonl"
    integrity = Integrity(KEY)
    assert save(audit, str(path), integrity=integrity) == 2
    assert len(load_verified(str(path), integrity=integrity)) == 2

    path.write_text(path.read_text().splitlines()[0] + "\n", encoding="utf-8")
    try:
        load_verified(str(path), integrity=integrity)
    except AuditTamperError:
        pass
    else:
        raise AssertionError("truncated audit must be rejected")


def test_shutdown_event_is_included_in_persisted_audit(tmp_path):
    system = _build_verified_system(tmp_path)
    system.shutdown()
    path = tmp_path / "shutdown-audit.jsonl"
    integrity = Integrity(KEY)
    save(system.audit, str(path), integrity=integrity)
    records = load_verified(str(path), integrity=integrity)
    assert records[-1]["event"] == "shutdown"



def test_integrity_restore_refuses_symlink_destination(tmp_path):
    target = tmp_path / "target"
    clean = tmp_path / "clean"
    target.mkdir()
    clean.mkdir()
    (target / "module.py").write_text("trusted = True\n")
    (clean / "module.py").write_text("trusted = True\n")
    baseline = tmp_path / ".ai_cyber" / "baseline.json"
    integrity = Integrity(KEY)
    write_baseline(str(target), str(baseline), integrity)

    outside = tmp_path / "outside.txt"
    outside.write_text("do not overwrite\n")
    (target / "module.py").unlink()
    (target / "module.py").symlink_to(outside)

    result = check(str(target), str(baseline), integrity, str(clean))
    assert result.ok is False
    assert "symlink" in result.reason
    assert outside.read_text() == "do not overwrite\n"


def test_it_tech_integrity_gate_refuses_symlink_source(tmp_path):
    target = tmp_path / "IT_tech.py"
    clean = tmp_path / "clean_IT_tech.py"
    baseline = tmp_path / ".ai_cyber" / "it-tech.json"
    clean.write_text("trusted_source = True\n")
    target.write_text("trusted_source = True\n")
    integrity = Integrity(KEY)
    write_file_baseline(str(target), str(baseline), integrity)

    outside = tmp_path / "outside.py"
    outside.write_text("do not overwrite\n")
    target.unlink()
    target.symlink_to(outside)

    result = check_file(str(target), str(baseline), integrity, str(clean))
    assert result.ok is False
    assert "symlink" in result.reason
    assert outside.read_text() == "do not overwrite\n"



def test_canonical_runtime_wires_it_tech_network_and_authority_gates(tmp_path):
    system = _build_verified_system(tmp_path)
    try:
        clean = _allowed_request(system)
        allowed = system.orchestrator.handle(clean)
        assert allowed.decision is Decision.ALLOW, allowed

        network_risk = replace(
            clean,
            request_id="req-network-risk-block",
            attributes={"network_risk": 0.9},
        )
        blocked_network = system.orchestrator.handle(network_risk)
        assert blocked_network.decision is Decision.BLOCK
        assert any(r.layer == "layer2" and r.decision is Decision.BLOCK
                   for r in blocked_network.layer_results)

        suspicious_posture = replace(
            clean,
            request_id="req-authority-posture-block",
            attributes={"it_tech_posture": "suspicious", "it_tech_risk": 0.8},
        )
        blocked_authority = system.orchestrator.handle(suspicious_posture)
        assert blocked_authority.decision is Decision.BLOCK
        assert any(r.layer == "layer3" and r.decision is Decision.BLOCK
                   for r in blocked_authority.layer_results)
    finally:
        system.shutdown()


@pytest.mark.parametrize(
    "attributes",
    [
        {"it_tech_posture": "suspicious"},
        {"it_tech_posture": "compromised"},
        {"it_tech_posture": "quarantined"},
        {"it_tech_posture": "unknown"},
        {"it_tech_posture": "unrecognized"},
        {"it_tech_risk": 0.7},
        {"it_tech_risk": True},
        {"it_tech_risk": float("nan")},
        {"it_tech_confidence": False},
        {"it_tech_confidence": 1.1},
        {"it_tech_posture": ["trusted"]},
    ],
)
def test_it_tech_authority_gate_fails_closed_for_risky_or_malformed_posture(attributes):
    from pathlib import Path
    from ai_cyber_os.layered_defense.it_tech_adapter import ITTechAuthorityGate

    root = Path(__file__).resolve().parents[1]
    gate = ITTechAuthorityGate(
        str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"),
        baseline_verified=True,
    )
    request = Request(
        request_id="req-authority-negative",
        principal="hydra-runtime",
        action="read",
        resource="hydra:run",
        payload="safe",
        credentials="unused",
        source="internal",
        attributes=attributes,
    )

    allowed, reason = gate.authorize(request)
    assert allowed is False
    assert reason


@pytest.mark.parametrize("risk", [True, float("nan"), -0.01, 1.01, 0.7])
def test_it_tech_network_gate_fails_closed_for_malformed_or_high_risk_telemetry(risk):
    from pathlib import Path
    from ai_cyber_os.layered_defense.it_tech_adapter import ITTechNetworkGate

    root = Path(__file__).resolve().parents[1]
    gate = ITTechNetworkGate(
        str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"),
        baseline_verified=True,
    )
    request = Request(
        request_id="req-network-negative",
        principal="hydra-runtime",
        action="read",
        resource="hydra:run",
        payload="safe",
        credentials="unused",
        source="internal",
        attributes={"network_risk": risk},
    )

    allowed, reason = gate.evaluate(request)
    assert allowed is False
    assert reason



def test_it_tech_network_engine_state_is_persistent_and_signal_history_is_bounded():
    from pathlib import Path
    from ai_cyber_os.layered_defense.it_tech_adapter import ITTechNetworkGate

    root = Path(__file__).resolve().parents[1]
    gate = ITTechNetworkGate(
        str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"),
        baseline_verified=True,
    )
    engine_identity = id(gate.engine)

    for index in range(140):
        request = Request(
            request_id=f"req-network-persistent-{index}",
            principal="hydra-runtime",
            action="read",
            resource="hydra:run",
            payload="safe",
            credentials="unused",
            source="internal",
            attributes={"network_risk": 0.0},
        )
        allowed, reason = gate.evaluate(request)
        assert allowed is True, reason

    snapshot = gate.snapshot()
    assert id(gate.engine) == engine_identity
    assert snapshot["active"] is True
    assert snapshot["observations"] <= 2 * gate._MAX_SIGNALS_PER_SOURCE
    assert snapshot["states"]["internal"]["label"] == "trusted"
    healthy, reason = gate.health_check()
    assert healthy is True, reason


def test_it_tech_network_gate_records_and_immediately_blocks_high_risk_evidence():
    from pathlib import Path
    from ai_cyber_os.layered_defense.it_tech_adapter import ITTechNetworkGate

    root = Path(__file__).resolve().parents[1]
    gate = ITTechNetworkGate(
        str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"),
        baseline_verified=True,
    )

    for index in range(2):
        request = Request(
            request_id=f"req-network-high-risk-{index}",
            principal="hydra-runtime",
            action="read",
            resource="hydra:run",
            payload="safe",
            credentials="unused",
            source="internal",
            attributes={"network_risk": 0.95},
        )
        allowed, reason = gate.evaluate(request)
        assert allowed is False
        assert "risk threshold" in reason

    snapshot = gate.snapshot()
    assert snapshot["observations"] == 2
    healthy, reason = gate.health_check()
    assert healthy is False
    assert "suspicious" in reason.lower() or "invariant" in reason.lower()



def test_it_tech_authority_health_check_reads_live_state_without_granting_authority():
    from datetime import datetime, timezone
    from pathlib import Path
    from ai_cyber_os.layered_defense.it_tech_adapter import ITTechAuthorityGate

    root = Path(__file__).resolve().parents[1]
    gate = ITTechAuthorityGate(
        str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"),
        baseline_verified=True,
    )
    decision_count = len(gate.engine.decisions())

    healthy, reason = gate.health_check()
    assert healthy is True, reason
    assert len(gate.engine.decisions()) == decision_count

    gate.engine.revoke(
        gate.principal_id,
        reason="unit test simulates a revoked runtime authority",
        at=datetime.now(timezone.utc),
    )
    healthy, reason = gate.health_check()
    assert healthy is False
    assert "revoked" in reason.lower()

    request = Request(
        request_id="req-revoked-authority",
        principal=gate.principal_id,
        action="read",
        resource="hydra:run",
        payload="safe",
        credentials="unused",
        source="internal",
    )
    allowed, reason = gate.authorize(request)
    assert allowed is False
    assert "revoked" in reason.lower()


def test_signed_baseline_evidence_seeds_trusted_internal_network_state():
    from pathlib import Path
    from ai_cyber_os.layered_defense.it_tech_adapter import ITTechNetworkGate

    root = Path(__file__).resolve().parents[1]
    gate = ITTechNetworkGate(
        str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"),
        baseline_verified=True,
    )
    snapshot = gate.snapshot()
    assert snapshot["states"]["internal"]["label"] == "trusted"
    healthy, reason = gate.health_check()
    assert healthy is True, reason


def test_runtime_builder_requires_an_explicit_verified_it_tech_source():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    source = str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py")

    with pytest.raises(StartupError, match="verified IT-Tech source is required"):
        build_system(key_provider=KEY)

    with pytest.raises(StartupError, match="signed IT-Tech source integrity verification"):
        build_system(
            config={"it_tech_source": source, "it_tech_integrity_verified": False},
            key_provider=KEY,
        )


def test_unverified_it_tech_gates_refuse_requests_and_report_unhealthy():
    from pathlib import Path
    from ai_cyber_os.layered_defense.it_tech_adapter import ITTechAuthorityGate, ITTechNetworkGate

    root = Path(__file__).resolve().parents[1]
    source = str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py")
    request = Request(
        request_id="unverified-it-tech-source",
        principal="hydra-runtime",
        action="read",
        resource="hydra:run",
        payload="safe",
        credentials="unused",
        source="internal",
    )

    network = ITTechNetworkGate(source, baseline_verified=False)
    allowed, reason = network.evaluate(request)
    assert allowed is False
    assert "integrity verification" in reason
    healthy, reason = network.health_check()
    assert healthy is False
    assert "integrity verification" in reason

    authority = ITTechAuthorityGate(source, baseline_verified=False)
    allowed, reason = authority.authorize(request)
    assert allowed is False
    assert "integrity verification" in reason
    healthy, reason = authority.health_check()
    assert healthy is False
    assert "integrity verification" in reason


def test_runtime_builder_rejects_missing_or_tampered_it_tech_baseline(tmp_path):
    import shutil
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    source = tmp_path / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"
    shutil.copy2(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py", source)
    state = tmp_path / ".ai_cyber"
    state.mkdir()

    with pytest.raises(StartupError, match="signed IT-Tech baseline is missing"):
        build_system(
            config={"it_tech_source": str(source), "it_tech_integrity_verified": True},
            key_provider=KEY,
        )

    baseline = state / "it_tech_baseline.json"
    write_file_baseline(str(source), str(baseline), Integrity(KEY))
    source.write_text("# source tampered after signing\n", encoding="utf-8")
    with pytest.raises(StartupError, match="signed IT-Tech baseline verification failed"):
        build_system(
            config={
                "it_tech_source": str(source),
                "it_tech_baseline_path": str(baseline),
                "it_tech_integrity_verified": True,
            },
            key_provider=KEY,
        )
