import json
from pathlib import Path

import pytest

from ai_cyber_os.knowledge import iter_records
from ai_cyber_os.threat_intel import (
    PARSERS,
    parse_attack_stix,
    parse_d3fend_jsonld,
    parse_mbc_stix,
    parse_suricata_rules,
)


def test_jsonld_graph_is_counted_as_nodes(tmp_path: Path):
    path = tmp_path / "d3fend.json"
    payload = {
        "@context": {"rdfs": "http://www.w3.org/2000/01/rdf-schema#"},
        "@graph": [
            {"@id": "d3f:Technique-A", "rdfs:label": {"@value": "Hardening", "@language": "en"}},
            {"@id": "d3f:Technique-B", "rdfs:label": {"@value": "Isolation", "@language": "en"}},
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    generic = list(iter_records(path, dataset="d3fend-fixture"))
    parsed = parse_d3fend_jsonld(path, validation_status="fixture-validated")

    assert len(generic) == 2
    assert [item["record_id"] for item in generic] == ["d3f:Technique-A", "d3f:Technique-B"]
    assert len(parsed) == 2
    assert parsed[0]["title"] == "Hardening"
    assert parsed[1]["record_id"] == "d3f:Technique-B"


def test_mbc_directory_counts_objects_not_bundle_files(tmp_path: Path):
    bundles = tmp_path / "bundles"
    bundles.mkdir()
    (bundles / "bundle-001.json").write_text(json.dumps({
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {"type": "malware", "id": "malware--1", "name": "Example one"},
            {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Example behavior"},
        ],
    }), encoding="utf-8")
    (bundles / "bundle-002.json").write_text(json.dumps({
        "type": "bundle",
        "id": "bundle--2",
        "objects": [{"type": "x-mbc-behavior", "id": "x-mbc-behavior--2", "name": "Example two"}],
    }), encoding="utf-8")
    (bundles / "manifest.json").write_text(json.dumps({"catalog": "metadata only"}), encoding="utf-8")

    records = parse_mbc_stix(bundles, validation_status="fixture-validated")

    assert len(list(bundles.glob("*.json"))) == 3
    assert len(records) == 3
    assert {record["record_id"] for record in records} == {
        "malware--1", "attack-pattern--1", "x-mbc-behavior--2"
    }
    assert all(record["source"] == "MITRE Malware Behavior Catalog" for record in records)
    assert {json.loads(record["metadata_json"])["bundle_file"] for record in records} == {
        "bundle-001.json", "bundle-002.json"
    }


def test_suricata_rules_separate_active_disabled_and_comments(tmp_path: Path):
    path = tmp_path / "test.rules"
    path.write_text(
        "alert tcp any any -> any 80 (msg:\"active-one\"; sid:1; rev:1;)\n"
        "# alert tcp any any -> any 81 (msg:\"disabled-one\"; sid:2; rev:1;)\n"
        "# a normal explanatory comment, not a rule\n"
        "drop http any any -> any any (msg:\"active-two\"; sid:3; rev:1;)\n"
        "# drop http any any -> any any (msg:\"disabled-two\"; sid:4; rev:1;)\n",
        encoding="utf-8",
    )

    records = parse_suricata_rules(path, validation_status="fixture-validated")
    active = [record for record in records if json.loads(record["metadata_json"])["status"] == "active"]
    disabled = [record for record in records if json.loads(record["metadata_json"])["status"] == "disabled"]

    assert len(active) == 2
    assert len(disabled) == 2
    assert all(record["record_id"].startswith("suricata:active:") for record in active)
    assert all(record["record_id"].startswith("suricata:disabled:") for record in disabled)
    assert "normal explanatory comment" not in " ".join(record["content"] for record in records)


def test_all_new_source_parser_kinds_are_registered():
    assert {"d3fend-jsonld", "mbc-stix", "suricata-rules"} <= set(PARSERS)


def test_lfs_pointer_is_never_parsed_as_attack_json(tmp_path: Path):
    path = tmp_path / "enterprise-attack.json"
    path.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:" + "a" * 64 + "\n"
        "size 123456\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Git LFS pointer"):
        parse_attack_stix(path)
