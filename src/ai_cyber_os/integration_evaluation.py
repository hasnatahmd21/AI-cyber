"""Deterministic evaluation layer for AI-CYBER intelligence integrations."""
from __future__ import annotations
import json, tempfile
from pathlib import Path
from typing import Any, Callable
from .malware_intel import parse_feature_jsonl
from .network_intel import parse_suricata_eve, parse_zeek_json
from .rag import build_context
from .runtime_intelligence import analyze
from .threat_intel import parse_nvd, parse_cisa_kev, parse_attack_stix, parse_cpe, parse_cwe_xml
from .knowledge import ingest_file

def _write_json(path: Path, value: Any) -> Path:
    path.write_text(json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8")
    return path

def _check_nvd_cvss(root: Path) -> None:
    p = _write_json(root / "nvd.json", {"vulnerabilities": [{"cve": {
        "id": "CVE-2099-1001", "descriptions": [{"lang": "en", "value": "fixture vulnerability"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}]})
    rows = parse_nvd(p, version="fixture", validation_status="fixture-validated")
    assert rows and rows[0]["record_id"] == "CVE-2099-1001"
    assert "9.8" in rows[0]["content"]

def _check_threat_parsers(root: Path) -> None:
    kev = _write_json(root / "kev.json", {"vulnerabilities": [{"cveID": "CVE-2099-1001"}]})
    assert parse_cisa_kev(kev)[0]["record_id"] == "CVE-2099-1001"
    attack = _write_json(root / "attack.json", {"objects": [{
        "type": "attack-pattern", "id": "attack-pattern--fixture",
        "name": "Command and Scripting Interpreter",
        "external_references": [{"external_id": "T1059"}]}]})
    assert parse_attack_stix(attack)[0]["record_id"] == "T1059"
    cpe = _write_json(root / "cpe.json", {"products": [{"cpeName": [{
        "cpe23Uri": "cpe:2.3:a:fixture:app:1.0:*:*:*:*:*:*:*"}]}]})
    assert parse_cpe(cpe)[0]["record_id"].startswith("cpe:2.3:")
    cwe = root / "cwe.xml"
    cwe.write_text('<Weaknesses><Weakness ID="79" Name="Improper Neutralization"><Description>fixture CWE</Description></Weakness></Weaknesses>', encoding="utf-8")
    assert parse_cwe_xml(cwe)[0]["record_id"] == "CWE-79"

def _check_network_and_malware(root: Path) -> None:
    suri = root / "eve.json"
    suri.write_text(json.dumps({"flow_id": 123, "event_type": "alert", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "proto": "TCP"}) + "\n", encoding="utf-8")
    assert parse_suricata_eve(suri)[0]["record_id"] == "123"
    zeek = root / "conn.json"
    zeek.write_text(json.dumps({"uid": "C-FIXTURE", "id.orig_h": "10.0.0.1"}) + "\n", encoding="utf-8")
    assert parse_zeek_json(zeek)[0]["record_id"] == "C-FIXTURE"
    malware = root / "malware.jsonl"
    malware.write_text(json.dumps({"sha256": "b" * 64, "family": "fixture-family", "features": {"pe_imports": ["CreateFileW"]}}) + "\n", encoding="utf-8")
    assert parse_feature_jsonl(malware)[0]["record_id"] == "b" * 64

def _check_ingestion_rag_runtime(root: Path) -> None:
    db = root / "knowledge.db"
    data = root / "evidence.jsonl"
    data.write_text(json.dumps({"id": "CVE-2099-1001", "description": "CWE-79 fixture"}) + "\n", encoding="utf-8")
    result = ingest_file(data, db_path=db, dataset="fixture-intelligence", source="offline-fixture", validation_status="fixture-validated")
    assert result["inserted"] == 1
    context = build_context("CVE-2099-1001", db_path=db)
    assert context["evidence_only"] is True and context["evidence"][0]["content_sha256"]
    runtime = analyze("CVE-2099-1001", db_path=db)
    assert runtime["answer"] is None and runtime["evidence_only"] is True
    assert runtime["evidence"][0]["validation_status"] == "fixture-validated"

def _run_group(name: str, checks: list[Callable[[Path], None]], root: Path) -> dict[str, Any]:
    results = {}
    for check in checks:
        try: check(root); results[check.__name__] = "PASS"
        except Exception as exc: results[check.__name__] = f"FAIL: {type(exc).__name__}: {exc}"
    passed = sum(v == "PASS" for v in results.values())
    return {"name": name, "tests_total": len(results), "passed": passed, "failed": len(results)-passed, "results": results, "verified": passed == len(results)}

def run_network_intelligence_evaluation() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="ai-cyber-network-eval-") as td:
        return _run_group("Phase 5 — Network/Threat Intelligence Integration",
            [_check_nvd_cvss, _check_threat_parsers, _check_network_and_malware, _check_ingestion_rag_runtime], Path(td))

def run_malware_intelligence_evaluation() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="ai-cyber-malware-eval-") as td:
        return _run_group("Phase 6 — Malware Intelligence Evaluation",
            [_check_network_and_malware, _check_ingestion_rag_runtime], Path(td))

def run_intelligence_evaluations() -> dict[str, Any]:
    network = run_network_intelligence_evaluation()
    malware = run_malware_intelligence_evaluation()
    return {"success": network["verified"] and malware["verified"], "phase5_network_intelligence": network, "phase6_malware_evaluation": malware}
