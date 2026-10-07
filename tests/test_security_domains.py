import json
from pathlib import Path

from ai_cyber_os.malware_intel import parse_feature_jsonl
from ai_cyber_os.network_intel import parse_suricata_eve, parse_zeek_json


def test_suricata_normalizer(tmp_path: Path):
    p = tmp_path / "eve.json"
    p.write_text(json.dumps({"flow_id": 42, "event_type": "flow", "proto": "TCP"}) + "\n", encoding="utf-8")
    rows = parse_suricata_eve(p)
    assert rows[0]["record_id"] == "42"
    assert rows[0]["dataset"] == "suricata-eve"


def test_zeek_normalizer(tmp_path: Path):
    p = tmp_path / "conn.json"
    p.write_text(json.dumps({"uid": "C123", "id.orig_h": "10.0.0.1"}) + "\n", encoding="utf-8")
    rows = parse_zeek_json(p)
    assert rows[0]["record_id"] == "C123"


def test_malware_features_require_identity(tmp_path: Path):
    p = tmp_path / "features.jsonl"
    p.write_text(json.dumps({"sha256": "a" * 64, "family": "example"}) + "\n", encoding="utf-8")
    rows = parse_feature_jsonl(p)
    assert rows[0]["record_id"] == "a" * 64
