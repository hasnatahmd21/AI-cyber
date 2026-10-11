from __future__ import annotations

import json

from ai_cyber_os.layered_defense.audit_telemetry import AuditLog
from ai_cyber_os.layered_defense.audit_store import load_verified, save, AuditTamperError
from ai_cyber_os.layered_defense.contracts import Decision, Request
from ai_cyber_os.layered_defense.crypto_integrity import Integrity, StaticKeyProvider
from ai_cyber_os.layered_defense.integrity_gate import build_baseline, check, write_baseline
from ai_cyber_os.layered_defense.runtime import StartupError, build_system


KEY = StaticKeyProvider({"default": b"unit-test-key-material-32-bytes!!"})


def _allowed_request(system, payload="safe"):
    system.trust.grant("hydra-runtime", "read", "hydra:")
    token = system.trust.issue_token("hydra-runtime")
    return Request("req-1", "hydra-runtime", "read", "hydra:run", payload=payload,
                   credentials=token, source="internal")


def test_pipeline_allows_clean_internal_hydra_request():
    system = build_system(key_provider=KEY)
    try:
        result = system.orchestrator.handle(_allowed_request(system))
        assert result.decision is Decision.ALLOW
        assert result.trace == ("barrier:allow", "layer1:allow", "layer2:allow", "layer3:allow")
    finally:
        system.shutdown()


def test_pipeline_blocks_shell_injection_before_hydra():
    system = build_system(key_provider=KEY)
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
    assert save(audit, str(path)) == 1
    records = load_verified(str(path))
    assert AuditLog.verify(records)
    assert "[REDACTED]" in path.read_text()
    path.write_text(path.read_text().replace('"started"', '"forged"'))
    try:
        load_verified(str(path))
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
    gate = ITTechAuthorityGate(str(root / "IT_tech__MERGED_ALL_FIXES_APPLIED.py"))
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
