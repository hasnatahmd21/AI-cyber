import json
from pathlib import Path

from ai_cyber_os.threat_intel import parse_nvd, parse_cisa_kev, parse_attack_stix, parse_cpe, ingest_source


def test_nvd_normalization(tmp_path: Path):
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps({
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2026-4242",
                "descriptions": [{"lang": "en", "value": "Example RCE"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}
            }
        }]
    }), encoding="utf-8")
    rows = parse_nvd(path, version="2.0", validation_status="source-checked")
    assert len(rows) == 1
    assert rows[0]["record_id"] == "CVE-2026-4242"
    assert rows[0]["validation_status"] == "source-checked"
    assert "CVE-2026-4242" in rows[0]["content"]
    assert "9.8" in rows[0]["content"]


def test_cisa_kev_normalization(tmp_path: Path):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps({"vulnerabilities": [{
        "cveID": "CVE-2026-4242",
        "vendorProject": "Example",
        "vulnerabilityName": "Example vulnerability"
    }]}), encoding="utf-8")
    rows = parse_cisa_kev(path)
    assert rows[0]["record_id"] == "CVE-2026-4242"


def test_attack_stix_normalization(tmp_path: Path):
    path = tmp_path / "attack.json"
    path.write_text(json.dumps({"objects": [{
        "type": "attack-pattern",
        "id": "attack-pattern--x",
        "name": "Command and Scripting Interpreter",
        "description": "Example",
        "external_references": [{"external_id": "T1059"}]
    }]}), encoding="utf-8")
    rows = parse_attack_stix(path)
    assert rows[0]["record_id"] == "T1059"


def test_source_ingestion_populates_relations(tmp_path: Path):
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps({"vulnerabilities": [{
        "cve": {"id": "CVE-2026-4242",
                 "descriptions": [{"lang": "en", "value": "CWE-89 example"}]}
    }]}), encoding="utf-8")
    db = tmp_path / "knowledge.db"
    result = ingest_source("nvd", path, db_path=db, validation_status="fixture-validated")
    assert result["inserted"] == 1
    from ai_cyber_os.intelligence import correlate
    evidence = correlate("CVE-2026-4242", db_path=str(db))
    assert evidence["related"]["CVE-2026-4242"][0]["record_id"] == "CVE-2026-4242"

def test_cpe_normalization(tmp_path: Path):
    path = tmp_path / "cpe.json"
    path.write_text(json.dumps({"products": [{"cpeName": [{"cpe23Uri": "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"}]}]}), encoding="utf-8")
    rows = parse_cpe(path)
    assert rows[0]["record_id"].startswith("cpe:2.3:")
