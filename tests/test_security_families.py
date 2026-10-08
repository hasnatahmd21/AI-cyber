from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from ai_cyber_os.security_families import (
    FAMILIES,
    SCHEMA_VERSION,
    SecurityFamilyError,
    SecurityFamilyStore,
    family_catalog,
    normalize_record,
)


def _record(**overrides):
    value = {
        "record_id": "CVE-TEST-001",
        "family": "vulnerability",
        "title": "Example vulnerability",
        "description": "A deterministic test record.",
        "cve_id": "CVE-2026-12345",
        "cwe_ids": ["CWE-79"],
        "capec_ids": ["CAPEC-63"],
        "attack_ids": ["T1059"],
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "severity": "HIGH",
        "evidence_refs": ["dataset-a:a.jsonl:r1"],
        "related_record_ids": ["weakness-1"],
        "source_dataset": "dataset-a",
        "source_artifact": "a.jsonl",
        "source_version": "1.0",
    }
    value.update(overrides)
    return value


def test_catalog_is_exactly_13_families():
    catalog = family_catalog()
    assert len(catalog) == 13
    assert tuple(item["family"] for item in catalog) == FAMILIES
    assert len({item["family"] for item in catalog}) == 13
    assert all(item["description"] for item in catalog)


def test_normalization_maps_common_security_identifiers():
    record = normalize_record(_record(cve=None, cwe=None, cwe_ids=None, cvss=None))
    assert record.cve_id == "CVE-2026-12345"
    assert record.cwe_ids == ("CWE-79",)
    assert record.cvss_score == 8.8
    assert record.attack_ids == ("T1059",)
    assert len(record.content_hash) == 64


@pytest.mark.parametrize("family", [None, "", "unknown", "vulnerabilities"])
def test_unknown_family_is_rejected(family):
    with pytest.raises(SecurityFamilyError):
        normalize_record(_record(family=family))


@pytest.mark.parametrize(
    "field,value",
    [
        ("cve_id", "CVE-20"),
        ("cwe_ids", ["CWE-x"]),
        ("capec_ids", ["CAPEC-x"]),
        ("attack_ids", ["ATTACK-foo"]),
        ("cvss_score", 10.1),
        ("cvss_score", float("nan")),
        ("record_id", ""),
        ("title", ""),
    ],
)
def test_identifier_and_metadata_validation(field, value):
    with pytest.raises(SecurityFamilyError):
        normalize_record(_record(**{field: value}))


def test_duplicate_reference_lists_are_rejected():
    with pytest.raises(SecurityFamilyError, match="duplicates"):
        normalize_record(_record(cwe_ids=["CWE-79", "CWE-79"]))


def test_canonical_hash_is_stable_under_mapping_order():
    a = normalize_record(_record())
    b = normalize_record(dict(reversed(list(_record().items()))))
    assert a.canonical_payload == b.canonical_payload
    assert a.content_hash == b.content_hash


def test_store_is_idempotent_and_traceable(tmp_path: Path):
    store = SecurityFamilyStore(tmp_path / "security.sqlite")
    record = normalize_record(_record())
    store.upsert(record)
    store.upsert(record)

    assert store.count() == 1
    assert store.count("vulnerability") == 1
    fetched = store.get(record.record_id)
    assert fetched == record

    integrity = store.verify_integrity()
    assert integrity["ok"] is True
    assert integrity["schema_version"] == SCHEMA_VERSION
    assert integrity["family_count"] == 13
    assert integrity["record_count"] == 1


def test_all_families_can_store_records(tmp_path: Path):
    store = SecurityFamilyStore(tmp_path / "families.sqlite")
    for index, family in enumerate(FAMILIES):
        store.upsert(
            normalize_record(
                _record(
                    record_id=f"record-{index}",
                    family=family,
                    cve_id=None,
                    cwe_ids=[],
                    capec_ids=[],
                    attack_ids=[],
                )
            )
        )
    assert store.count() == 13
    assert all(store.count(family) == 1 for family in FAMILIES)
    assert store.verify_integrity()["ok"] is True


def test_database_tampering_is_detected(tmp_path: Path):
    store = SecurityFamilyStore(tmp_path / "tamper.sqlite")
    record = normalize_record(_record())
    store.upsert(record)

    with sqlite3.connect(store.db_path) as db:
        db.execute(
            "UPDATE security_records SET payload_json=? WHERE record_id=?",
            ('{"record_id":"CVE-TEST-001","family":"vulnerability","title":"tampered"}', record.record_id),
        )

    result = store.verify_integrity()
    assert result["ok"] is False
    assert any("content hash mismatch" in error for error in result["errors"])


def test_payload_json_is_canonical_and_not_executable(tmp_path: Path):
    store = SecurityFamilyStore(tmp_path / "canonical.sqlite")
    record = normalize_record(_record(description='x"}; DROP TABLE security_records; --'))
    store.upsert(record)

    with sqlite3.connect(store.db_path) as db:
        payload = db.execute(
            "SELECT payload_json FROM security_records WHERE record_id=?",
            (record.record_id,),
        ).fetchone()[0]
        assert json.loads(payload)["description"].startswith('x"};')
        assert db.execute(
            "SELECT count(*) FROM security_records"
        ).fetchone()[0] == 1


def test_invalid_limit_is_rejected(tmp_path: Path):
    store = SecurityFamilyStore(tmp_path / "limits.sqlite")
    with pytest.raises(SecurityFamilyError):
        store.list_family("vulnerability", 0)
    with pytest.raises(SecurityFamilyError):
        store.list_family("vulnerability", 1001)
    with pytest.raises(SecurityFamilyError):
        store.list_family("not-a-family", 1)
